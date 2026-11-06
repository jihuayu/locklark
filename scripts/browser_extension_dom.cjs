// Real Chromium DOM checks for the exact static function used by the extension.
// No product hooks, native approvals, extension privileges or secrets are faked.
const playwright = require(
  process.env.LOCKLARK_TEST_PLAYWRIGHT || "../web/node_modules/playwright",
);
const assert = require("node:assert/strict");
const path = require("node:path");
(async () => {
  const browserName = process.env.LOCKLARK_TEST_BROWSER || "chromium";
  assert(["chromium", "firefox"].includes(browserName));
  const browser = await playwright[browserName].launch({
    headless: true,
    args: browserName === "chromium" ? ["--no-sandbox"] : [],
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
        assert.deepEqual(result.values.filter(Boolean), [
          "fixture-user",
          "fixture-password",
        ]);
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
      true,
    );
    await check(basic + basic, false);
    await check("<div inert>" + basic + "</div>", false);
    await check('<base href="https://evil.test/">' + basic, false);
    const capture = async (markup, allowed, options = {}) => {
      html = markup;
      await page.goto("https://example.test/login");
      await page.addScriptTag({
        path: path.resolve(__dirname, "../browser-extension/core.js"),
      });
      const result = await page.evaluate(
        ({ username, password, deadline, expected }) => {
          const inputs = [...document.querySelectorAll("input")];
          for (const input of inputs)
            input.value = input.type === "password" ? password : username;
          const before = inputs.map((input) => input.value);
          let events = 0;
          for (const type of ["input", "change", "submit"])
            document.addEventListener(type, (event) => {
              events++;
              event.preventDefault();
            });
          const value = LocklarkCore.fillDocument(
            expected,
            "",
            "",
            Date.now() + deadline,
            true,
          );
          return {
            refused: value === false,
            exact:
              !!value &&
              Object.keys(value).sort().join(",") === "password,username" &&
              value.username === username &&
              value.password === password,
            unchanged: inputs.every(
              (input, index) => input.value === before[index],
            ),
            events,
          };
        },
        {
          username: options.username ?? "合成采集用户",
          password: options.password ?? "Synthetic-capture-🔐",
          deadline: options.deadline ?? 1500,
          expected: options.expected ?? "https://example.test",
        },
      );
      assert(
        result.unchanged && result.events === 0,
        "Capture modified or submitted the controlled document",
      );
      assert(
        allowed ? result.exact : result.refused,
        "Unexpected static capture result",
      );
    };
    await capture(basic, true);
    await capture(basic, true, { username: "" });
    await capture(basic, false, { password: "" });
    await capture(basic, false, { deadline: -1 });
    await capture(basic, false, { deadline: 2500 });
    await capture(basic, false, { expected: "https://other.test" });
    await capture(basic, true, {
      username: "é".repeat(8192),
      password: "🔐".repeat(4096),
    });
    await capture(basic, false, { username: "é".repeat(8193) });
    await capture(basic, false, { password: "🔐".repeat(4097) });
    for (const invalid of ["\ud800", "\udc00", "x\ud800y"]) {
      await capture(basic, false, { username: invalid });
      await capture(basic, false, { password: invalid });
    }
    for (const field of ['name="username"', 'name="password"']) {
      for (const replacement of [
        " hidden",
        " disabled",
        " readonly",
        ' style="display:none"',
        ' style="visibility:hidden"',
        ' style="opacity:0"',
      ])
        await capture(basic.replace(field, field + replacement), false);
    }
    for (const markup of [
      "<fieldset disabled>" + basic + "</fieldset>",
      "<div inert>" + basic + "</div>",
      '<div aria-hidden="true">' + basic + "</div>",
      basic + basic,
      basic.replace(
        '<input type="password"',
        '<input name="other"><input type="password"',
      ),
      basic.replace('action="/login"', 'action="https://evil.test/login"'),
      basic.replace(
        "<button>",
        '<button formaction="https://evil.test/login">',
      ),
      basic.replace("<form ", '<form id="login" ') +
        '<button form="login" formaction="https://evil.test/login">External submitter</button>',
      '<base href="https://evil.test/">' + basic,
    ])
      await capture(markup, false);
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
    assert(
      await frame.evaluate(() => {
        document.querySelector("input[type=password]").value =
          "Synthetic-frame-value";
        return (
          LocklarkCore.fillDocument(
            location.origin,
            "",
            "",
            Date.now() + 1500,
            true,
          ) === false
        );
      }),
      "Iframe capture was not refused",
    );
    await require("./browser_otp_dom.cjs")(page);
    await require("./browser_login_parity_dom.cjs")(page);
    console.log(
      browserName +
        " DOM: login fill, static capture and OTP probe/fill with fixed clocks; no writes/events/submission; Unicode/UTF-8/surrogate bounds; hidden/disabled/readonly/ambiguous/cross-action/base/iframe refusals passed",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error.message);
  console.error("Browser DOM acceptance failed");
  process.exitCode = 1;
});

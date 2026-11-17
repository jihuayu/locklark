// Actual popup actions and native approvals; the only code oracle is an
// independent Python HMAC over the private fixture. No product authorization hook.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

import { browserFixtureExecutable } from "./browser_save_acceptance.mjs";

export const otpHTML =
  '<!doctype html><html><title>Locklark OTP acceptance</title><body><form id="otp-form" action="/verify"><input id="otp-code" autocomplete="one-time-code"><button>Verify</button></form><script>window.submits=0;document.addEventListener("submit",event=>{event.preventDefault();window.submits++;});</script></body></html>';

// Resolve the fixture once per configure call through the same helper as the
// vault observer: LOCKLARK_BROWSER_FIXTURE is reused, otherwise the historical
// state/fixture-observer build path is kept.
export function configureOTPFixture(driver, digits) {
  const { root, state, env, go } = driver;
  return execFileSync(
    browserFixtureExecutable({
      go: go || process.env.LOCKLARK_GO || "go",
      root,
      env,
      state,
    }),
    [
      "-configure-otp",
      join(state, "vault/fixture.json"),
      "-digits",
      String(digits),
    ],
    { cwd: root, env, stdio: ["ignore", "ignore", "pipe"], timeout: 20000 },
  );
}

export async function acceptBrowserOTP(driver) {
  const {
    fixture,
    origin,
    phase,
    input,
    inspect,
    observe,
    openPopup,
    reconnect,
    navigate,
    pageEval,
    root,
    state,
    env,
    go,
  } = driver;
  fixture.OTPCodes = [];
  let stage = "otp",
    popup;
  const knownWindows = new Set();
  const step = (value) => {
    const counter = Math.floor(Date.now() / 30000);
    if (!knownWindows.has(counter)) {
      for (const digits of [6, 8]) {
        const expected = JSON.parse(
          execFileSync("python3", [join(root, "scripts/browser_otp_hmac.py")], {
            input: JSON.stringify({
              seed: fixture.OTPSeed,
              digits,
              first: counter,
              last: counter + 1,
            }),
            stdio: ["pipe", "pipe", "pipe"],
            timeout: 5000,
          }).toString(),
        );
        fixture.OTPCodes.push(...expected);
        expected.fill("");
      }
      knownWindows.add(counter);
    }
    phase(stage + ":" + value);
  };
  const delay = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds));
  const wait = async (check) => {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      if (await check()) return;
      await delay(75);
    }
    throw Error("OTP acceptance condition timed out");
  };
  const empty = () =>
    pageEval(() => {
      const documents = [
        document,
        ...[...document.querySelectorAll("iframe")]
          .map((frame) => frame.contentDocument)
          .filter(Boolean),
      ];
      return (
        documents.every((doc) =>
          [
            ...doc.querySelectorAll('input[autocomplete="one-time-code"]'),
          ].every((input) => input.value === ""),
        ) && window.submits === 0
      );
    });
  const configure = (digits) => configureOTPFixture(driver, digits);
  const page = async (variant) => {
    step("controlled-document");
    await navigate(origin + "/otp-acceptance");
    await pageEval((variant) => {
      const input = document.querySelector("#otp-code"),
        form = input.form;
      if (variant === "ambiguous") form.append(input.cloneNode());
      if (variant === "iframe") {
        form.remove();
        const frame = document.createElement("iframe");
        frame.src = "/otp-frame";
        document.body.append(frame);
      }
      if (variant === "no-form") (document.body.append(input), form.remove());
    }, variant);
    assert(await empty(), "OTP page is not initially empty");
  };
  const choose = async () => {
    step("target-observe");
    const row = observe().rows.find((row) => row.id === fixture.SeedID);
    assert(
      row && /^[a-f0-9]{64}$/.test(row.revision),
      "OTP target metadata missing",
    );
    const selector =
      '#candidates [data-item-id="' +
      row.id +
      '"][data-item-revision="' +
      row.revision +
      '"] [data-action="otp"]';
    step("popup-open");
    popup = await openPopup();
    step("refresh-enabled");
    await wait(async () => (await popup.disabled("#refresh")) === false);
    step("refresh-click");
    await popup.click("#refresh");
    step("fresh-candidate");
    await wait(
      async () =>
        (await popup.disabled("#refresh")) === false &&
        (await popup.count(selector)) === 1 &&
        (await popup.disabled(selector)) === false,
    );
    step("explicit-action");
    await popup.click(selector);
  };
  const pending = async () => {
    await choose();
    step("native-pending");
    input([{ wait_label: "批准填充验证码" }]);
    assert(await empty(), "OTP released before native approval");
  };
  const finished = async () => {
    step("native-cleared");
    await wait(() => {
      const control = inspect().controls["批准填充验证码"];
      return !control.present || !control.enabled || !control.showing;
    });
    popup = await openPopup();
    await wait(async () => (await popup.disabled("#refresh")) === false);
  };
  const unchanged = (before) => {
    step("authenticated-oracle");
    const after = observe();
    assert(
      before.snapshot_digest === after.snapshot_digest &&
        JSON.stringify(before.rows) === JSON.stringify(after.rows),
      "OTP modified stored items",
    );
    return after;
  };
  const clearWindow = async () => {
    // Schedule a new explicit action away from a boundary, never retry a failed
    // request or ask the product to generate the next period automatically.
    const remaining = 30000 - (Date.now() % 30000);
    if (remaining < 8000) await delay(remaining + 100);
  };
  const positive = async (digits) => {
    stage = "otp-" + digits + ":positive";
    await clearWindow();
    await page("normal");
    const before = observe();
    await pending();
    step("approve");
    const started = Date.now();
    input([{ click_label: "批准填充验证码" }]);
    step("code-delivery");
    await wait(async () =>
      pageEval(() => document.querySelector("#otp-code").value.length > 0),
    );
    const received = await pageEval(() => ({
      code: document.querySelector("#otp-code").value,
      submits: window.submits,
    }));
    const ended = Date.now();
    step("independent-hmac");
    const expected = JSON.parse(
      execFileSync("python3", [join(root, "scripts/browser_otp_hmac.py")], {
        input: JSON.stringify({
          seed: fixture.OTPSeed,
          digits,
          first: Math.floor(started / 30000),
          last: Math.floor(ended / 30000),
        }),
        stdio: ["pipe", "pipe", "pipe"],
        timeout: 5000,
      }).toString(),
    );
    fixture.OTPCodes.push(...expected, received.code);
    assert(
      new RegExp("^[0-9]{" + digits + "}$").test(received.code) &&
        expected.includes(received.code) &&
        received.submits === 0,
      "OTP did not match independent HMAC or submitted a form",
    );
    if (env.LOCKLARK_TEST_FAILURE_STAGE === "otp-page-arguments") {
      step("driver-arguments-failure");
      await pageEval((code) => {
        document.querySelector("#otp-code").value = code;
        throw Error("Controlled OTP driver argument failure");
      }, received.code);
      throw Error("Controlled OTP driver failure missing");
    }
    received.code = "";
    expected.fill("");
    await finished();
    const after = unchanged(before);
    const events = after.otp_events.slice(before.otp_events.length);
    assert(
      events.length === 1 &&
        events[0].result === "intent" &&
        events[0].item_id === fixture.SeedID &&
        events[0].base_revision ===
          before.rows.find((row) => row.id === fixture.SeedID).revision,
      "OTP intent audit does not match its authenticated target",
    );
    const text = String(await popup.text("body"));
    assert(
      !fixture.OTPCodes.some((code) => text.includes(code)),
      "Popup exposed an OTP code",
    );
  };

  step("reconnect");
  await reconnect();
  await positive(6);
  for (const variant of [
    "reject",
    "cancel",
    "navigate",
    "cross-action",
    "cross-submitter",
    "lock",
  ]) {
    stage = "otp:" + variant;
    await page("normal");
    const before = observe();
    await pending();
    step("one-action");
    if (variant === "reject") input([{ click_label: "拒绝填充验证码" }]);
    else if (variant === "cancel") {
      popup = await openPopup();
      await wait(async () => (await popup.disabled("#cancel-otp")) === false);
      await popup.click("#cancel-otp");
    } else if (variant === "navigate")
      await navigate(origin + "/otp-new-document");
    else if (variant === "lock")
      input([{ click_label: "立即锁定" }, { wait_label: "解锁" }]);
    else {
      await pageEval((variant) => {
        if (variant === "cross-action")
          document.querySelector("form").action = "https://other.test/verify";
        else {
          const submitter = document.createElement("button");
          submitter.setAttribute("form", "otp-form");
          submitter.formAction = "https://other.test/verify";
          document.body.append(submitter);
        }
      }, variant);
      input([{ click_label: "批准填充验证码" }]);
    }
    if (variant !== "lock") await finished();
    assert(await empty(), "Refused or revoked OTP reached a field");
    unchanged(before);
    if (variant === "lock") await reconnect();
  }
  for (const variant of ["iframe", "ambiguous", "no-form"]) {
    stage = "otp:" + variant;
    await page(variant);
    await choose();
    step("fixed-refusal");
    await wait(async () => (await popup.text("#status")).includes("拒绝"));
    assert(await empty(), "Unsupported OTP document changed");
    const approval = inspect().controls["批准填充验证码"];
    assert(
      !approval.present || !approval.enabled || !approval.showing,
      "Unsupported OTP document reached native approval",
    );
  }
  stage = "otp:revision-changed";
  await page("normal");
  await pending();
  configure(8);
  input([{ click_label: "批准填充验证码" }]);
  await finished();
  assert(await empty(), "Stale OTP revision was filled");
  await positive(8);
  stage = "otp:not-configured";
  configure(0);
  await page("normal");
  await pending();
  input([{ click_label: "批准填充验证码" }]);
  await finished();
  assert(await empty(), "Unconfigured OTP was filled");
  configure(6);
  stage = "otp:original-window-exhausted";
  await clearWindow();
  await page("normal");
  await pending();
  step("window-boundary");
  const until = (Math.floor(Date.now() / 30000) + 1) * 30000;
  const pause = until - Date.now() - 1100;
  if (pause > 0) await delay(pause);
  step("single-approval");
  input([{ click_label: "批准填充验证码" }]);
  assert(
    Date.now() < until,
    "OTP boundary experiment crossed into the next window before approval returned",
  );
  await finished();
  if (Date.now() < until + 250) await delay(until + 250 - Date.now());
  assert(
    await empty(),
    "Short original OTP window filled or automatically fetched a later code",
  );
  console.log(
    "PASS: real OTP native approval, independent Python HMAC for 6/8 digits, intent audit, refusal/cancel/navigation/lock/revision/form/iframe and original-window exhaustion; no submission",
  );
}

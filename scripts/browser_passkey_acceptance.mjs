// Extends the real native/Chromium driver. No vault unlock/approval hooks.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHash, createPublicKey, verify } from "node:crypto";
import { acceptPasskeyManagement } from "./browser_passkey_management_acceptance.mjs";
import { acceptConditionalPasskey } from "./browser_conditional_passkey_acceptance.mjs";
import { acceptOtherProvider } from "./browser_other_provider_acceptance.mjs";
export async function acceptBrowserPasskey({
  page,
  browser,
  origin,
  input,
  fixture,
  openPopup,
  eventually,
  phase,
  observe,
  reconnect,
}) {
  phase("quick-pair");
  let popup = await openPopup();
  await popup.click("#disconnect");
  input([], true, { wait_absent: true });
  popup = await openPopup();
  await popup.click("#connect");
  input([
    { click_label: "金库文件" },
    { text: fixture.Path },
    { click_label: "主密码" },
    { text: fixture.Password },
    { click_label: "Secret Key" },
    { text: fixture.Secret },
    { click_label: "解锁" },
  ]);
  input([{ click_label: "连接并启用快捷填充" }]);
  popup = await openPopup();
  await popup.click("#auto-login");
  // Dismiss the real extension popup and exercise the actual closed-shadow UI
  // with physical CDP pointer events, not dispatchEvent or privileged messages.
  await page.bringToFront();
  await page.keyboard.press("Escape");
  const cdp = await browser.newCDPSession(page);
  async function inlinePresent(label) {
    const { root } = await cdp.send("DOM.getDocument", { depth: -1, pierce: true });
    const walk = node => (node.nodeName === "BUTTON" && (node.children || []).some(c => c.nodeValue === label)) ||
      [...(node.children || []), ...(node.shadowRoots || [])].some(walk);
    return walk(root);
  }
  async function inlineClick(label) {
    let node;
    await eventually(async () => {
      const { root } = await cdp.send("DOM.getDocument", {
        depth: -1,
        pierce: true,
      });
      const walk = (n) => {
        if (
          n.nodeName === "BUTTON" &&
          (n.children || []).some((c) => c.nodeValue === label)
        )
          return n;
        for (const child of [...(n.children || []), ...(n.shadowRoots || [])]) {
          const found = walk(child);
          if (found) return found;
        }
      };
      node = walk(root);
      return !!node;
    }, "Inline control unavailable");
    const { model } = await cdp.send("DOM.getBoxModel", {
      nodeId: node.nodeId,
    });
    await page.mouse.click(
      (model.content[0] + model.content[4]) / 2,
      (model.content[1] + model.content[5]) / 2,
    );
  }
  phase("quick-fill-and-auto-login");
  await page.goto(origin + "/login");
  await page.locator("#username").click();
  await inlineClick("Browser acceptance login");
  await eventually(
    () => page.evaluate(() => window.submits === 1),
    "Quick fill did not submit exactly once",
  );
  assert.equal(await page.locator("#password").inputValue(), fixture.Value);
  phase("passkey-create");
  await page.goto(origin + "/passkey");
  const challenge = Buffer.from(
    "synthetic-create-challenge-0123456789",
  ).toString("base64url");
  const rp = new URL(origin).hostname;
  await page.evaluate(
    ({ rp, challenge }) => {
      const decode = (s) =>
        Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
          c.charCodeAt(0),
        );
      window.passkeyResult = null;
      window.passkeyError = null;
      navigator.credentials
        .create({
          publicKey: {
            rp: { id: rp, name: "Synthetic acceptance" },
            user: {
              id: new Uint8Array([1, 2, 3]),
              name: "passkey-test",
              displayName: "Synthetic user",
            },
            challenge: decode(challenge),
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: {
              residentKey: "required",
              userVerification: "required",
            },
            extensions: { credProps: true },
          },
        })
        .then(
          (c) => {
            window.passkeyResult = {
              json: c.toJSON(),
              instance: c instanceof PublicKeyCredential,
              response: c.response instanceof AuthenticatorAttestationResponse,
              algorithm: c.response.getPublicKeyAlgorithm(),
              publicKey: Array.from(new Uint8Array(c.response.getPublicKey())),
            };
          },
          () => {
            window.passkeyError = true;
          },
        );
    },
    { rp, challenge },
  );
  await inlineClick("保存到 Locklark");
  input([
    { wait_label: "验证主密码" },
    { click_label: "验证主密码" },
    { text: fixture.Password },
    { click_label: "验证 Secret Key" },
    { text: fixture.Secret },
    { click_label: "创建新登录并保存 Passkey" },
  ]);
  await page.bringToFront();
  await eventually(
    () => page.evaluate(() => !!window.passkeyResult || window.passkeyError),
    "Creation did not complete",
  );
  const created = await page.evaluate(() => window.passkeyResult);
  assert(
    created?.instance && created.response && created.algorithm === -7,
    "Credential API contract",
  );
  const client = JSON.parse(
    Buffer.from(created.json.response.clientDataJSON, "base64url"),
  );
  assert.equal(client.origin, origin);
  assert.equal(client.challenge, challenge);
  assert.equal(client.type, "webauthn.create");
  assert.equal(created.json.clientExtensionResults.credProps.rk, true);
  const auth = Buffer.from(
    created.json.response.authenticatorData,
    "base64url",
  );
  assert.deepEqual(
    auth.subarray(0, 32),
    createHash("sha256").update(rp).digest(),
  );
  assert.equal(auth[32] & 0x45, 0x45);
  let registration, verifier;
  if (process.env.LOCKLARK_TEST_WEBAUTHN_SERVER) {
    verifier = createRequire(import.meta.url)(
      process.env.LOCKLARK_TEST_WEBAUTHN_SERVER,
    );
    registration = await verifier.verifyRegistrationResponse({
      response: created.json,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: rp,
      requireUserVerification: true,
    });
    assert.equal(
      registration.verified,
      true,
      "Independent WebAuthn registration rejected",
    );
  }
  phase("passkey-get");
  const getChallenge = Buffer.from(
    "synthetic-get-challenge-9876543210",
  ).toString("base64url");
  await page.evaluate(
    ({ id, rp, challenge }) => {
      const decode = (s) =>
        Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
          c.charCodeAt(0),
        );
      window.passkeyResult = null;
      window.passkeyError = null;
      navigator.credentials
        .get({
          publicKey: {
            rpId: rp,
            challenge: decode(challenge),
            allowCredentials: [{ type: "public-key", id: decode(id) }],
            userVerification: "required",
          },
        })
        .then(
          (c) => {
            window.passkeyResult = {
              json: c.toJSON(),
              instance: c instanceof PublicKeyCredential,
              response: c.response instanceof AuthenticatorAssertionResponse,
            };
          },
          () => {
            window.passkeyError = true;
          },
        );
    },
    { id: created.json.id, rp, challenge: getChallenge },
  );
  await inlineClick("使用 Locklark 登录");
  input([
    { wait_label: "验证主密码" },
    { click_label: "验证主密码" },
    { text: fixture.Password },
    { click_label: "验证 Secret Key" },
    { text: fixture.Secret },
    { click_label: "登录：" + rp + " · passkey-test · passkey-test" },
  ]);
  await page.bringToFront();
  await eventually(
    () => page.evaluate(() => !!window.passkeyResult || window.passkeyError),
    "Assertion did not complete",
  );
  const signed = await page.evaluate(() => window.passkeyResult);
  assert(signed?.instance && signed.response);
  const clientRaw = Buffer.from(
    signed.json.response.clientDataJSON,
    "base64url",
  );
  const getClient = JSON.parse(clientRaw);
  assert.equal(getClient.origin, origin);
  assert.equal(getClient.challenge, getChallenge);
  assert.equal(getClient.type, "webauthn.get");
  const assertionAuth = Buffer.from(
    signed.json.response.authenticatorData,
    "base64url",
  );
  assert.equal(assertionAuth[32] & 5, 5);
  assert.deepEqual(
    assertionAuth.subarray(0, 32),
    createHash("sha256").update(rp).digest(),
  );
  const publicKey = createPublicKey({
    key: Buffer.from(created.publicKey),
    format: "der",
    type: "spki",
  });
  assert(
    verify(
      "sha256",
      Buffer.concat([
        assertionAuth,
        createHash("sha256").update(clientRaw).digest(),
      ]),
      publicKey,
      Buffer.from(signed.json.response.signature, "base64url"),
    ),
    "Relying party signature verification failed",
  );
  if (verifier) {
    const result = await verifier.verifyAuthenticationResponse({
      response: signed.json,
      expectedChallenge: getChallenge,
      expectedOrigin: origin,
      expectedRPID: rp,
      credential: registration.registrationInfo.credential,
      requireUserVerification: true,
    });
    assert.equal(
      result.verified,
      true,
      "Independent WebAuthn authentication rejected",
    );
    console.log(
      "Independent WebAuthn server: registration and authentication verified",
    );
  }
  phase("passkey-abort");
  await page.evaluate(() => {
    window.abortResult = null;
    const controller = new AbortController();
    navigator.credentials
      .get({
        signal: controller.signal,
        publicKey: { challenge: new Uint8Array(32) },
      })
      .then(
        () => (window.abortResult = "unexpected"),
        (e) => (window.abortResult = e.name),
      );
    controller.abort();
  });
  await eventually(
    () => page.evaluate(() => window.abortResult === "AbortError"),
    "AbortSignal not honored",
  );
  if (process.env.LOCKLARK_TEST_PASSKEY_CONDITIONAL === "1") {
    await acceptConditionalPasskey({
      origin, fixture, first: created.json, pageEval: (fn, arg) => page.evaluate(fn, arg),
      clickDocument: async selector => { input([], false); await page.bringToFront(); await page.locator(selector).click(); },
      inlineClick, inlinePresent,
      inspectConditional: async () => {
        const { root } = await cdp.send("DOM.getDocument", { depth: -1, pierce: true });
        const state = { panels: 0, choices: 0, expectedLabel: false };
        const visit = node => {
          const attrs = node.attributes || [];
          if (attrs.includes("data-locklark-conditional")) state.panels++;
          if (attrs.includes("data-locklark-passkey-choice")) {
            state.choices++;
            if ((node.children || []).some(c => c.nodeValue === "Synthetic user · passkey-test")) state.expectedLabel = true;
          }
          for (const child of [...(node.children || []), ...(node.shadowRoots || [])]) visit(child);
        };
        visit(root); return state;
      },
      focusPage: () => page.bringToFront(), navigate: url => page.goto(url),
      eventually, input, observe, phase, openPopup, reconnect,
    });
  }
  if (process.env.LOCKLARK_TEST_OTHER_PROVIDER === "1") {
    input([], false);
    await page.bringToFront();
    await acceptOtherProvider({
      page, cdp, origin, first: created.json, inlineClick,
      eventually, observe, phase,
    });
  }
  if (process.env.LOCKLARK_TEST_PASSKEY_MANAGEMENT === "1") {
    await acceptPasskeyManagement({
      origin, fixture, first: created.json, openPopup, observe, reconnect,
      pageEval: (fn, arg) => page.evaluate(fn, arg), inlineClick,
      focusPage: () => page.bringToFront(),
      dismissPopup: async () => { await page.bringToFront(); await page.keyboard.press("Escape"); },
      eventually, input, phase,
    });
  }
  await cdp.detach();
}

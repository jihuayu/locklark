// Controlled relying party and physical input; no privileged product messages.
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { createRequire } from "node:module";
import { passkeyChoiceLabel } from "./browser_passkey_management_acceptance.mjs";

function prepareFields() {
  document.querySelector("#username").autocomplete = "username webauthn";
  document.activeElement?.blur();
  window.conditionalMetadataExposed = false;
  window.conditionalBridgeFacts = { requests: 0, capability: null, fallback: false };
  window.addEventListener("message", event => {
    if (event.source !== window || event.origin !== location.origin) return;
    const value = event.data;
    if (value?.source === "locklark-request-v1" && value.type === "get" && value.conditional === true)
      window.conditionalBridgeFacts.requests++;
    if (value?.source === "locklark-capability-v1")
      window.conditionalBridgeFacts.capability = value.conditional === true;
    if (value?.source === "locklark-result-v1" && value.fallback === true)
      window.conditionalBridgeFacts.fallback = true;
    if (String(value?.source || "").startsWith("locklark-") &&
        ["passkeys", "candidates", "user_name", "display_name", "item_id", "revision"]
          .some(key => Object.hasOwn(value, key))) window.conditionalMetadataExposed = true;
  });
}
function startConditional({ rp, challenge }) {
  window.conditionalController?.abort();
  const controller = new AbortController();
  window.conditionalController = controller;
  window.conditionalResult = null;
  window.conditionalError = null;
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  navigator.credentials.get({
    mediation: "conditional", signal: controller.signal,
    publicKey: { rpId: rp, challenge: decode(challenge), timeout: 1, userVerification: "required" },
  }).then(value => {
    window.conditionalResult = { json: value.toJSON(), instance: value instanceof PublicKeyCredential };
  }, error => { window.conditionalError = error?.name || "error"; });
}
function readConditional() {
  return {
    result: window.conditionalResult, error: window.conditionalError,
    metadataExposed: window.conditionalMetadataExposed,
    lightDOMChoices: document.querySelectorAll("[data-locklark-passkey-choice]").length,
  };
}


// Two credentials under one parent share the public account label. The picker
// must therefore expose both full labels and the caller must select the exact
// second credential rather than accepting the first record.
export async function acceptConditionalSibling({
  origin, fixture, first, second, pageEval, clickDocument, inlineClick, inlinePresent,
  focusPage, navigate, eventually, input, observe, phase,
}) {
  const rp = new URL(origin).hostname;
  assert.equal(rp, "login.locklark.test", "Controlled conditional RP required");
  const hint = id => id.slice(0, 6) + "…" + id.slice(-4);
  const firstLabel = "Synthetic user · passkey-test · " + hint(first.id);
  const secondLabel = "Synthetic user · passkey-test · " + hint(second.id);
  assert.notEqual(firstLabel, secondLabel, "Sibling public selectors must differ");
  const factors = [
    { wait_label: "验证主密码" }, { click_label: "验证主密码" }, { text: fixture.Password },
    { click_label: "验证 Secret Key" }, { text: fixture.Secret },
  ];
  phase("passkey-conditional:two-siblings-document");
  await navigate(origin + "/passkey?conditional-siblings=1");
  await focusPage();
  await pageEval(prepareFields);
  await eventually(async () =>
    (await pageEval(async () => await PublicKeyCredential.isConditionalMediationAvailable())) === true,
  "Conditional availability missing", 20000);
  const nativeChoice = () => passkeyChoiceLabel({
    rp, title: rp + " · passkey-test", username: "passkey-test", credentialId: second.id,
  });
  const noApproval = () => {
    const controls = input([], true, { inspect: true }).controls || {};
    assert(!controls["验证主密码"]?.showing && !controls[nativeChoice()]?.showing,
      "Conditional sibling waiting opened approval before account selection");
  };
  const before = observe();
  const challenge = Buffer.from("synthetic-conditional-two-siblings").toString("base64url");
  await pageEval(startConditional, { rp, challenge });
  noApproval();
  let state = await pageEval(readConditional);
  assert.equal(state.metadataExposed, false, "Sibling account metadata crossed into MAIN");
  assert.equal(state.lightDOMChoices, 0, "Sibling account metadata escaped the closed shadow");
  assert.equal(observe().snapshot_digest, before.snapshot_digest,
    "Conditional sibling listing changed the vault snapshot");
  await clickDocument("#username");
  await eventually(() => inlinePresent(secondLabel), "Second sibling conditional choice missing", 20000);
  assert.equal(await inlinePresent(firstLabel), true, "First sibling conditional choice missing");
  assert.equal(await inlinePresent("Synthetic user · passkey-test"), false,
    "Ambiguous bare account label must not be offered for two siblings");
  noApproval();
  state = await pageEval(readConditional);
  assert.equal(state.metadataExposed, false, "Sibling account metadata crossed into MAIN");
  assert.equal(state.lightDOMChoices, 0, "Sibling account metadata escaped the closed shadow");
  assert.equal(observe().snapshot_digest, before.snapshot_digest,
    "Conditional sibling selection changed the vault snapshot before the selected get");
  phase("passkey-conditional:select-second-sibling");
  // noApproval() is a native control inspection: the XTest driver raises and
  // focuses the native app window, and the browser-side coordinate probe cannot
  // see that overlapping window. Browser focus must therefore be the last focus
  // action, with a fresh probe of the selector, before the single physical
  // selection below.
  await focusPage();
  await eventually(() => inlinePresent(secondLabel),
    "Second sibling conditional choice missing after restoring browser focus", 20000);
  await inlineClick(secondLabel);
  input([...factors, {
    click_label: passkeyChoiceLabel({
      rp, title: rp + " · passkey-test", username: "passkey-test", credentialId: second.id,
    }),
  }]);
  await focusPage();
  await eventually(async () => {
    const current = await pageEval(readConditional);
    return !!(current.result || current.error);
  }, "Conditional sibling assertion did not finish", 20000);
  state = await pageEval(readConditional);
  assert(!state.error && state.result?.instance, "Conditional second sibling was rejected");
  assert.equal(state.result.json.id, second.id, "Conditional picker signed with the first sibling");
  assert.equal(state.metadataExposed, false, "Sibling selection exposed account metadata to MAIN");
  assert.equal(state.lightDOMChoices, 0, "Sibling selection left private metadata in light DOM");
  const clientBytes = Buffer.from(state.result.json.response.clientDataJSON, "base64url");
  const client = JSON.parse(clientBytes);
  assert.equal(client.origin, origin); assert.equal(client.challenge, challenge);
  assert.equal(client.type, "webauthn.get");
  const auth = Buffer.from(state.result.json.response.authenticatorData, "base64url");
  assert.deepEqual(auth.subarray(0, 32), createHash("sha256").update(rp).digest());
  assert.equal(auth[32] & 5, 5, "Presence and fresh verification required");
  const publicKey = createPublicKey({ key: Buffer.from(second.response.publicKey, "base64url"), format: "der", type: "spki" });
  assert(verify("sha256", Buffer.concat([auth, createHash("sha256").update(clientBytes).digest()]),
    publicKey, Buffer.from(state.result.json.response.signature, "base64url")),
  "Conditional second sibling signature verification failed");
  console.log("PASS: real conditional account picker offers both full sibling selectors and signs with the exact second credential");
}

export async function acceptConditionalPasskey({
  origin, fixture, first, pageEval, clickDocument, inlineClick, inlinePresent,
  focusPage, navigate, eventually, input, observe, phase, inspectConditional, openPopup, reconnect,
}) {
  const rp = new URL(origin).hostname;
  assert.equal(rp, "login.locklark.test", "Controlled conditional RP required");
  const label = "Synthetic user · passkey-test";
  const nativeChoice = () => passkeyChoiceLabel({ rp, title: rp + " · passkey-test", username: "passkey-test", credentialId: first.id });
  const noApproval = () => {
    const controls = input([], true, { inspect: true }).controls || {};
    assert(!controls["验证主密码"]?.showing && !controls[nativeChoice()]?.showing,
      "Conditional waiting opened approval before account selection");
  };
  const start = async name => {
    const challenge = Buffer.from("synthetic-conditional-" + name).toString("base64url");
    await pageEval(startConditional, { rp, challenge });
    return challenge;
  };
  phase("passkey-conditional:controlled-document");
  // The preceding full OTP journey leaves its own split-field document open.
  // Navigate through the actual driver to the login fixture required here.
  await navigate(origin + "/passkey?conditional-start=1");
  phase("passkey-conditional:capability");
  await focusPage();
  await pageEval(prepareFields);
  const availability = [];
  try {
    await eventually(async () => {
      const supported = await pageEval(async () => await PublicKeyCredential.isConditionalMediationAvailable());
      availability.push(supported === true);
      return supported === true;
    }, "Conditional availability missing", 20000);
  } catch (error) {
    console.log("Conditional capability state: " + JSON.stringify(await pageEval(() => ({
      visible: document.visibilityState === "visible", focused: document.hasFocus(),
      method: typeof PublicKeyCredential.isConditionalMediationAvailable === "function",
      bridge: window.conditionalBridgeFacts,
    }))));
    throw error;
  }
  console.log("Conditional capability attempts: " + JSON.stringify(availability));
  const before = observe();
  phase("passkey-conditional:no-prompt-before-focus");
  await start("abort");
  await new Promise(resolve => setTimeout(resolve, 250));
  let state = await pageEval(readConditional);
  assert(!state.error && !state.result, "Conditional request applied the RP timeout");
  assert.equal(await inlinePresent(label), false, "Account panel appeared without field focus");
  noApproval();
  phase("passkey-conditional:focus-and-abort");
  await clickDocument("#username");
  phase("passkey-conditional:await-account-list");
  console.log("Conditional input state: " + JSON.stringify(await pageEval(() => ({
    focused: document.activeElement === document.querySelector("#username"),
    documentFocused: document.hasFocus(), visible: document.visibilityState === "visible",
    webauthnInput: document.querySelector("#username").getAttribute("autocomplete") === "username webauthn",
    settled: !!(window.conditionalError || window.conditionalResult),
  }))));
  try {
    await eventually(() => inlinePresent(label), "Conditional account list missing after input focus", 20000);
  } catch (error) {
    console.log("Conditional bridge state: " + JSON.stringify(await pageEval(() => window.conditionalBridgeFacts)));
    if (inspectConditional) console.log("Conditional panel state: " + JSON.stringify(await inspectConditional()));
    throw error;
  }
  noApproval();
  state = await pageEval(readConditional);
  assert.equal(state.metadataExposed, false, "Account metadata crossed into the MAIN bridge");
  assert.equal(state.lightDOMChoices, 0, "Account metadata escaped the closed shadow");
  assert.equal(observe().snapshot_digest, before.snapshot_digest, "Account listing changed the vault snapshot");
  await pageEval(() => { window.conditionalController.abort(); });
  await eventually(async () => (await pageEval(readConditional)).error === "AbortError", "Conditional abort failed");
  await eventually(async () => !(await inlinePresent(label)), "Aborted conditional panel survived");
  noApproval();
  phase("passkey-conditional:select-account");
  const challenge = await start("selected-account");
  await clickDocument("#username");
  // The click above already restores browser focus; repeat it as the last focus
  // action so the single physical selection can never follow a native snapshot.
  await focusPage();
  await inlineClick(label);
  input([
    { wait_label: "验证主密码" }, { click_label: "验证主密码" }, { text: fixture.Password },
    { click_label: "验证 Secret Key" }, { text: fixture.Secret }, { click_label: nativeChoice() },
  ]);
  await focusPage();
  await eventually(async () => {
    const current = await pageEval(readConditional);
    return !!(current.result || current.error);
  }, "Conditional assertion did not finish", 20000);
  state = await pageEval(readConditional);
  assert(!state.error && state.result?.instance, "Selected conditional credential was rejected");
  const response = state.result.json;
  assert.equal(response.id, first.id, "Different account signed the conditional request");
  assert.equal(state.metadataExposed, false, "Conditional selection exposed account metadata to MAIN");
  const clientBytes = Buffer.from(response.response.clientDataJSON, "base64url");
  const client = JSON.parse(clientBytes);
  assert.equal(client.origin, origin); assert.equal(client.challenge, challenge);
  assert.equal(client.type, "webauthn.get");
  const auth = Buffer.from(response.response.authenticatorData, "base64url");
  assert.deepEqual(auth.subarray(0, 32), createHash("sha256").update(rp).digest());
  assert.equal(auth[32] & 5, 5, "Presence and fresh verification required");
  const publicKey = createPublicKey({ key: Buffer.from(first.response.publicKey, "base64url"), format: "der", type: "spki" });
  assert(verify("sha256", Buffer.concat([auth, createHash("sha256").update(clientBytes).digest()]),
    publicKey, Buffer.from(response.response.signature, "base64url")), "Conditional RP rejected the signature");
  if (process.env.LOCKLARK_TEST_WEBAUTHN_SERVER) {
    const server = createRequire(import.meta.url)(process.env.LOCKLARK_TEST_WEBAUTHN_SERVER);
    const registration = await server.verifyRegistrationResponse({ response: first,
      expectedChallenge: JSON.parse(Buffer.from(first.response.clientDataJSON, "base64url")).challenge,
      expectedOrigin: origin, expectedRPID: rp, requireUserVerification: true });
    assert.equal(registration.verified, true);
    const checked = await server.verifyAuthenticationResponse({ response,
      expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rp,
      credential: registration.registrationInfo.credential, requireUserVerification: true });
    assert.equal(checked.verified, true, "Independent verifier rejected conditional authentication");
  }
  phase("passkey-conditional:navigation-cleanup");
  await clickDocument("#username");
  await start("navigation");
  await eventually(() => inlinePresent(label), "Conditional list missing before navigation");
  await navigate(origin + "/passkey?conditional-reloaded=1");
  assert.equal(await inlinePresent(label), false, "Old conditional list survived navigation");
  noApproval();
  phase("passkey-conditional:disconnect-cleanup");
  await focusPage();
  await pageEval(prepareFields);
  await start("disconnect");
  await clickDocument("#username");
  await eventually(() => inlinePresent(label), "Conditional list missing before disconnect");
  const popup = await openPopup();
  await popup.click("#disconnect");
  await eventually(async () => (await pageEval(readConditional)).error === "NotAllowedError",
    "Disconnect left a conditional request alive", 15000);
  await focusPage();
  assert.equal(await inlinePresent(label), false, "Disconnected conditional list survived");
  await reconnect();
  await focusPage();
  phase("passkey-conditional:complete");
  console.log("PASS: real conditional Passkey input suggestions, no early approval, ignored timeout, abort, private metadata, selected-account signature, navigation and disconnect cleanup");
}

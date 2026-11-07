// Standard RP APIs and physical native/popup controls; no product test hooks.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { verifyRegistrationResponse, verifyAuthenticationResponse } from "./browser_firefox_passkey_acceptance.mjs";

function prepareSignalPage() {
  window.signalBridgeLeak = false;
  window.addEventListener("message", event => {
    if (event.source !== window || event.origin !== location.origin) return;
    const value = event.data;
    if (!String(value?.source || "").startsWith("locklark-")) return;
    if (["passkeys", "changes", "signalResult", "count", "affected"].some(key => Object.hasOwn(value, key)) ||
        value.type === "passkey-signal-accepted") window.signalBridgeLeak = true;
  });
  return ["signalUnknownCredential", "signalAllAcceptedCredentials", "signalCurrentUserDetails"]
    .every(name => typeof PublicKeyCredential[name] === "function");
}
function startSignalCredential({ create, rp, name, id, challenge }) {
  const bytes = raw => Uint8Array.from(atob(raw.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  window.signalCredential = null;
  window.signalCredentialError = null;
  const publicKey = create ? {
    rp: { id: rp, name: "Synthetic signals acceptance" },
    user: { id: new Uint8Array([27, 28, 29]), name, displayName: "Synthetic signal account" },
    challenge: bytes(challenge), pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    extensions: { credProps: true },
  } : {
    rpId: rp, challenge: bytes(challenge),
    allowCredentials: [{ type: "public-key", id: bytes(id) }], userVerification: "required",
  };
  navigator.credentials[create ? "create" : "get"]({ publicKey }).then(value => {
    window.signalCredential = { json: value.toJSON(), instance: value instanceof PublicKeyCredential };
  }, error => { window.signalCredentialError = error?.name || "error"; });
}
function startSignalCall({ method, options }) {
  window.signalCall = { settled: false, error: null, valueType: null };
  PublicKeyCredential[method](options).then(value => {
    window.signalCall = { settled: true, error: null, valueType: typeof value };
  }, error => {
    window.signalCall = { settled: true, error: error?.name || "error", valueType: null };
  });
}

export async function acceptPasskeySignals({
  origin, fixture, first, pageEval, inlineClick, focusPage, navigate,
  openPopup, dismissPopup, eventually, input, observe, phase,
}) {
  const rp = new URL(origin).hostname;
  assert.equal(rp, "login.locklark.test", "Controlled signal RP required");
  const userId = Buffer.from([27, 28, 29]).toString("base64url");
  const names = ["signal-one", "signal-two"];
  const confirm = "确认应用这些更新", cancel = "取消（不做任何更改）";
  const factors = [
    { wait_label: "验证主密码" }, { click_label: "验证主密码" }, { text: fixture.Password },
    { click_label: "验证 Secret Key" }, { text: fixture.Secret },
  ];
  const verifier = process.env.LOCKLARK_TEST_WEBAUTHN_SERVER
    ? createRequire(import.meta.url)(process.env.LOCKLARK_TEST_WEBAUTHN_SERVER) : null;
  const peers = new Map();
  const challenge = () => randomBytes(32).toString("base64url");
  const nativeGone = async () => eventually(() => {
    const controls = input([], true, { inspect: true }).controls || {};
    return [confirm, cancel, "取消尚未提交的更新"].every(label => !controls[label]?.showing);
  }, "Signal owner review did not close", 20000);
  const noPageOutcome = async () => assert.equal(await pageEval(() => window.signalBridgeLeak), false,
    "Local signal outcome or account metadata reached MAIN");
  const waitCredential = async () => {
    await eventually(async () => await pageEval(() => !!window.signalCredential || !!window.signalCredentialError),
      "Signal fixture ceremony did not finish", 20000);
    const state = await pageEval(() => ({ value: window.signalCredential, error: window.signalCredentialError }));
    assert(!state.error && state.value?.instance, "Signal fixture credential was refused");
    return state.value.json;
  };
  const peerRegistration = async registration => {
    if (!verifier || peers.has(registration.id)) return;
    const client = JSON.parse(Buffer.from(registration.response.clientDataJSON, "base64url"));
    const checked = await verifier.verifyRegistrationResponse({ response: registration,
      expectedChallenge: client.challenge, expectedOrigin: origin, expectedRPID: rp, requireUserVerification: true });
    assert.equal(checked.verified, true, "Independent signal registration rejected");
    peers.set(registration.id, checked.registrationInfo.credential);
  };
  const assertCredential = async (registration, name) => {
    await dismissPopup(); await focusPage();
    const expectedChallenge = challenge();
    await pageEval(startSignalCredential, { create: false, rp, id: registration.id, challenge: expectedChallenge });
    await inlineClick("使用 Locklark 登录");
    input([...factors, { click_label: "登录：" + rp + " · " + name + " · " + name }]);
    await focusPage();
    const signed = await waitCredential();
    assert.equal(signed.id, registration.id, "Signal changed credential identity");
    const accepted = verifyAuthenticationResponse({ response: signed, expectedChallenge,
      expectedOrigin: origin, expectedRPID: rp,
      publicKey: verifyRegistrationResponse({ response: registration,
        expectedChallenge: JSON.parse(Buffer.from(registration.response.clientDataJSON, "base64url")).challenge,
        expectedOrigin: origin, expectedRPID: rp, requireUserVerification: true }).publicKey,
      requireUserVerification: true });
    assert.equal(accepted.verified, true, "Signal changed credential signing material");
    await peerRegistration(registration);
    if (verifier) {
      const checked = await verifier.verifyAuthenticationResponse({ response: signed, expectedChallenge,
        expectedOrigin: origin, expectedRPID: rp, credential: peers.get(registration.id), requireUserVerification: true });
      assert.equal(checked.verified, true, "Independent signal assertion rejected");
    }
  };
  const call = async (method, options, ownerExpected) => {
    await dismissPopup(); await focusPage();
    const before = observe();
    await pageEval(startSignalCall, { method, options });
    await eventually(async () => (await pageEval(() => window.signalCall)).settled,
      "Browser signal Promise did not resolve independently", 20000);
    const result = await pageEval(() => window.signalCall);
    assert(!result.error && result.valueType === "undefined", "Browser signal result changed");
    if (ownerExpected) {
      input([{ wait_label: confirm }]);
      assert.equal(observe().snapshot_digest, before.snapshot_digest, "Signal committed before owner confirmation");
    }
    await noPageOutcome();
    return before;
  };
  const apply = async before => {
    input([{ click_label: confirm }]);
    await eventually(() => observe().snapshot_digest !== before.snapshot_digest, "Owner-confirmed signal did not persist", 20000);
    await nativeGone(); await focusPage(); await noPageOutcome();
  };
  const title = name => rp + " · " + name;
  const itemId = name => {
    const rows = observe().rows.filter(row => row.title === title(name));
    assert.equal(rows.length, 1, "Signal login record missing or ambiguous");
    return rows[0].id;
  };
  const rowSelector = id => '#vault-list [data-item-id="' + id + '"]';
  const keys = async () => {
    const popup = await openPopup();
    await eventually(async () => await popup.disabled("#search-input") === false, "Signal vault not ready");
    await popup.click('#filter-tabs [data-filter="passkeys"]');
    await eventually(async () => await popup.disabled("#search-input") === false, "Signal Passkey list not ready");
    return popup;
  };
  const metadata = async (id, name, display) => {
    const popup = await keys();
    await eventually(async () => await popup.count(rowSelector(id)) === 1, "Signal credential missing from public list");
    await popup.click(rowSelector(id));
    await eventually(async () => await popup.visible("#passkey-detail"), "Signal metadata missing");
    assert.equal(await popup.text("#passkey-username"), name, "Signal username metadata mismatch");
    assert.equal(await popup.text("#passkey-display-name"), display, "Signal display metadata mismatch");
    await dismissPopup();
  };
  const listed = async (present, absent) => {
    const popup = await keys();
    await eventually(async () => {
      for (const id of present) if (await popup.count(rowSelector(id)) !== 1) return false;
      for (const id of absent) if (await popup.count(rowSelector(id)) !== 0) return false;
      return true;
    }, "Signal removed an accepted credential or retained a rejected one", 20000);
    await dismissPopup();
  };
  phase("passkey-signal:controlled-document");
  await navigate(origin + "/passkey?signals=1"); await focusPage();
  assert.equal(await pageEval(prepareSignalPage), true, "Selected browser lacks native signal APIs");
  const registrations = [];
  for (const name of names) {
    phase("passkey-signal:create-" + name);
    const expectedChallenge = challenge();
    await pageEval(startSignalCredential, { create: true, rp, name, challenge: expectedChallenge });
    await inlineClick("保存到 Locklark");
    input([...factors, { click_label: "创建新登录并保存 Passkey" }]);
    await focusPage();
    const registration = await waitCredential();
    verifyRegistrationResponse({ response: registration, expectedChallenge,
      expectedOrigin: origin, expectedRPID: rp, requireUserVerification: true });
    await peerRegistration(registration); registrations.push(registration);
  }
  assert.notEqual(registrations[0].id, registrations[1].id);
  const ids = names.map(itemId), originalId = itemId("passkey-test");
  const details = { rpId: rp, userId, name: "signal-renamed", displayName: "Synthetic renamed" };
  phase("passkey-signal:cancel-details");
  let before = await call("signalCurrentUserDetails", details, true);
  input([{ click_label: cancel }]); await nativeGone();
  assert.equal(observe().snapshot_digest, before.snapshot_digest, "Cancel changed the signal snapshot");
  await metadata(ids[0], names[0], "Synthetic signal account");
  phase("passkey-signal:apply-details");
  before = await call("signalCurrentUserDetails", details, true); await apply(before);
  for (const id of ids) await metadata(id, "signal-renamed", "Synthetic renamed");
  for (let i = 0; i < ids.length; i++)
    assert(observe().rows.some(row => row.id === ids[i] && row.title === title(names[i])), "Signal renamed login fields");
  phase("passkey-signal:renamed-credential-signature");
  await assertCredential(registrations[1], names[1]);
  phase("passkey-signal:accepted-credentials");
  before = await call("signalAllAcceptedCredentials", { rpId: rp, userId,
    allAcceptedCredentialIds: [registrations[1].id] }, true); await apply(before);
  await listed([ids[1], originalId], [ids[0]]);
  assert(observe().rows.some(row => row.id === ids[0]), "Signal deleted the login record");
  phase("passkey-signal:missing-credential");
  before = await call("signalUnknownCredential", { rpId: rp, credentialId: registrations[0].id }, false);
  assert.equal(observe().snapshot_digest, before.snapshot_digest, "Missing signal changed the snapshot");
  phase("passkey-signal:unknown-credential");
  before = await call("signalUnknownCredential", { rpId: rp, credentialId: registrations[1].id }, true); await apply(before);
  await listed([originalId], ids);
  assert(ids.every(id => observe().rows.some(row => row.id === id)), "Signal deleted a login record");
  phase("passkey-signal:unrelated-account-signature");
  await assertCredential(first, "passkey-test"); await noPageOutcome();
  phase("passkey-signal:complete");
  console.log("PASS: real browser signal APIs preserve native Promise behavior, require owner confirmation, preserve keys and logins, isolate accounts and never return local outcomes to MAIN");
}

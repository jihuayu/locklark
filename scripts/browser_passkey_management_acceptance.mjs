// Real popup controls and navigator.credentials only; no privileged mutation hooks.
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { createRequire } from "node:module";

function startCredential({ create, rp, id, challenge, account, abortAfter }) {
  const decode = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const controller = new AbortController();
  window.managementResult = null;
  window.managementError = null;
  const options = create ? {
    rp: { id: rp, name: "Synthetic management acceptance" },
    user: { id: new Uint8Array([4, 5, 6]), name: account, displayName: "Other synthetic account" },
    challenge: decode(challenge), pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    extensions: { credProps: true },
  } : {
    rpId: rp, challenge: decode(challenge),
    allowCredentials: [{ type: "public-key", id: decode(id) }], userVerification: "required",
  };
  const timer = abortAfter ? setTimeout(() => controller.abort(), abortAfter) : null;
  navigator.credentials[create ? "create" : "get"]({ publicKey: options, signal: controller.signal }).then(
    credential => {
      if (timer) clearTimeout(timer);
      window.managementResult = { json: credential.toJSON(), instance: credential instanceof PublicKeyCredential };
    }, error => {
      if (timer) clearTimeout(timer);
      window.managementError = error?.name || "error";
    },
  );
}
function credentialResult() { return { result: window.managementResult, error: window.managementError }; }

export async function acceptPasskeyManagement({
  origin, fixture, first, openPopup, pageEval, inlineClick, focusPage,
  dismissPopup, reconnect, eventually, input, observe, phase,
}) {
  const rp = new URL(origin).hostname;
  assert.equal(rp, "login.locklark.test", "Allowlisted synthetic management RP required");
  const account = "passkey-other";
  const firstTitle = rp + " · passkey-test";
  const secondTitle = rp + " · " + account;
  const factors = [
    { wait_label: "验证主密码" }, { click_label: "验证主密码" }, { text: fixture.Password },
    { click_label: "验证 Secret Key" }, { text: fixture.Secret },
  ];
  const verifier = process.env.LOCKLARK_TEST_WEBAUTHN_SERVER
    ? createRequire(import.meta.url)(process.env.LOCKLARK_TEST_WEBAUTHN_SERVER) : null;
  let secondRegistration;
  const waitResult = async () => {
    await eventually(async () => {
      const state = await pageEval(credentialResult);
      return !!(state.result || state.error);
    }, "Management WebAuthn request did not finish", 20000);
    return pageEval(credentialResult);
  };
  const checkSignature = (registration, signed, challenge) => {
    const client = Buffer.from(signed.response.clientDataJSON, "base64url");
    const parsed = JSON.parse(client);
    assert.equal(parsed.origin, origin); assert.equal(parsed.challenge, challenge);
    assert.equal(parsed.type, "webauthn.get");
    const auth = Buffer.from(signed.response.authenticatorData, "base64url");
    assert.deepEqual(auth.subarray(0, 32), createHash("sha256").update(rp).digest());
    assert.equal(auth[32] & 5, 5, "User presence and fresh verification required");
    const key = createPublicKey({ key: Buffer.from(registration.response.publicKey, "base64url"), format: "der", type: "spki" });
    assert(verify("sha256", Buffer.concat([auth, createHash("sha256").update(client).digest()]),
      key, Buffer.from(signed.response.signature, "base64url")), "Management RP rejected the signature");
  };
  const get = async (registration, name) => {
    await dismissPopup();
    const challenge = Buffer.from("synthetic-managed-get-" + name).toString("base64url");
    await pageEval(startCredential, { create: false, rp, id: registration.id, challenge });
    await inlineClick("使用 Locklark 登录");
    input([...factors, { click_label: "登录：" + rp + " · " + name + " · " + name }]);
    await focusPage();
    const state = await waitResult();
    assert(!state.error && state.result?.instance, "Managed credential assertion rejected");
    checkSignature(registration, state.result.json, challenge);
    if (verifier && registration.id === second.id) {
      const checked = await verifier.verifyAuthenticationResponse({
        response: state.result.json, expectedChallenge: challenge, expectedOrigin: origin,
        expectedRPID: rp, credential: secondRegistration.registrationInfo.credential,
        requireUserVerification: true,
      });
      assert.equal(checked.verified, true, "Independent verifier rejected remaining account");
    }
  };

  phase("passkey-management:create-second-account");
  await dismissPopup();
  const challenge = Buffer.from("synthetic-managed-create-second-account").toString("base64url");
  await pageEval(startCredential, { create: true, rp, challenge, account });
  await inlineClick("保存到 Locklark");
  input([...factors, { click_label: "创建新登录并保存 Passkey" }]);
  await focusPage();
  const created = await waitResult();
  assert(!created.error && created.result?.instance, "Second account creation rejected");
  const second = created.result.json;
  assert.notEqual(second.id, first.id, "Accounts must have different credential IDs");
  const client = JSON.parse(Buffer.from(second.response.clientDataJSON, "base64url"));
  assert.equal(client.origin, origin); assert.equal(client.challenge, challenge);
  assert.equal(client.type, "webauthn.create");
  assert(second.response.publicKey && second.response.publicKeyAlgorithm === -7,
    "Public ES256 key metadata required");
  if (verifier) {
    secondRegistration = await verifier.verifyRegistrationResponse({
      response: second, expectedChallenge: challenge, expectedOrigin: origin,
      expectedRPID: rp, requireUserVerification: true,
    });
    assert.equal(secondRegistration.verified, true, "Independent verifier rejected second registration");
  }
  const itemID = title => {
    const rows = observe().rows.filter(row => row.title === title);
    assert.equal(rows.length, 1, "Exactly one controlled account must persist");
    return rows[0].id;
  };
  const firstID = itemID(firstTitle), secondID = itemID(secondTitle);
  const row = id => '#vault-list [data-item-id="' + id + '"]';
  const keys = async () => {
    const popup = await openPopup();
    await eventually(async () => await popup.disabled("#search-input") === false, "Vault readiness missing");
    await popup.click('#filter-tabs [data-filter="passkeys"]');
    await eventually(async () => await popup.disabled("#search-input") === false, "Passkey list did not settle");
    return popup;
  };
  const openFirst = async () => {
    const popup = await keys();
    await eventually(async () => await popup.count(row(firstID)) === 1, "First account missing from management list");
    await popup.click(row(firstID));
    await eventually(async () => await popup.visible("#passkey-detail"), "Passkey metadata unavailable");
    assert(String(await popup.text("#passkey-detail")).includes(rp), "Stored RP metadata missing");
    return popup;
  };
  phase("passkey-management:list-two-accounts");
  let popup = await keys();
  await eventually(async () => await popup.count(row(firstID)) === 1 && await popup.count(row(secondID)) === 1,
    "Both accounts must appear in server-filtered Passkey list");
  await popup.click(row(firstID));
  await eventually(async () => await popup.visible("#passkey-detail"), "First Passkey detail unavailable");
  phase("passkey-management:preservation-edit");
  await popup.click("#detail-edit");
  for (const [name, value] of [["password", fixture.Value], ["notes", fixture.UpdateValue]]) {
    phase("passkey-management:preservation-edit-" + name);
    await popup.click('#editor-fields [data-field="' + name + '"]');
    await popup.selectAll(); await popup.insertText(value);
  }
  phase("passkey-management:preservation-save");
  await popup.click("#editor-save");
  await eventually(async () => await popup.visible("#passkey-detail"), "Editing lost the existing Passkey");
  phase("passkey-management:cancel-delete");
  await popup.click("#passkey-remove");
  await eventually(async () => await popup.visible("#passkey-remove-confirm"), "Removal confirmation missing");
  await popup.click("#passkey-remove-cancel");
  await eventually(async () => !(await popup.visible("#passkey-remove-confirm")), "Cancellation did not close confirmation");
  await get(first, "passkey-test");

  phase("passkey-management:delete-one");
  popup = await openFirst();
  await popup.click("#passkey-remove");
  await eventually(async () => await popup.visible("#passkey-remove-confirm"), "Removal confirmation missing");
  await popup.click("#passkey-remove-confirm");
  await eventually(async () => !(await popup.visible("#passkey-detail")), "Passkey removal did not persist", 30000);
  assert(observe().rows.some(item => item.id === firstID), "Removing a Passkey deleted its login");
  for (const [name, value] of [["password", fixture.Value], ["notes", fixture.UpdateValue]]) {
    const field = '[data-field-id="' + name + '"]';
    await popup.click(field + ' [data-action="toggle-reveal"]');
    await eventually(async () => await popup.text(field + ' .field-value') === value,
      "Removing a Passkey changed another protected field");
    await popup.click(field + ' [data-action="toggle-reveal"]');
  }
  phase("passkey-management:removed-credential-unavailable");
  await dismissPopup();
  await pageEval(startCredential, { create: false, rp, id: first.id,
    challenge: Buffer.from("synthetic-deleted-credential-get").toString("base64url"), abortAfter: 2000 });
  await inlineClick("使用 Locklark 登录");
  const removed = await waitResult();
  assert(!removed.result && removed.error, "Deleted credential produced a result");
  const controls = input([], true, { inspect: true }).controls || {};
  assert(!controls["登录：" + rp + " · passkey-test · passkey-test"]?.showing,
    "Deleted credential remained an approvable native choice");
  phase("passkey-management:other-account-signature");
  await get(second, account);
  phase("passkey-management:reconnect-persistence");
  await reconnect();
  popup = await keys();
  await eventually(async () => await popup.count(row(secondID)) === 1 && await popup.count(row(firstID)) === 0,
    "Passkey-only list did not preserve the removal after reconnect");
  await get(second, account);
  phase("passkey-management:complete");
  console.log("PASS: real Passkey multi-account list, cancel, separate removal, retained login/password/notes, deleted-credential refusal, other-account signature and reconnect persistence");
  return { separateRemoval: true, secondAccountVerified: true, reconnectVerified: true };
}

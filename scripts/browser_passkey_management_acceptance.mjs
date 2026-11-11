// Real popup controls and navigator.credentials only; no privileged mutation hooks.
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { createRequire } from "node:module";

export function passkeyCredentialHint(credentialId) {
  assert.equal(typeof credentialId, "string");
  return credentialId.length <= 8 ? credentialId : credentialId.slice(0, 8) + "…";
}
export function passkeyPopupHint(credentialId) {
  return typeof credentialId === "string" && credentialId.length >= 12
    ? credentialId.slice(0, 6) + "…" + credentialId.slice(-6) : "";
}
// Mirrors internal/desktop/browser.go passkeyChoiceLabel exactly: the RP, the
// stored title, the account and the public credential hint. No fuzzy matching.
export function passkeyChoiceLabel({ create = false, rp, title, username, credentialId = "", existing = 0 }) {
  let label = (create ? "保存到：" : "登录：") + rp + " · " + (title || "（无标题）") + " · " + (username || "");
  if (!create && credentialId) label += " · 凭据 " + passkeyCredentialHint(credentialId);
  if (create) {
    label += "（已有 " + existing + " 个 Passkey）";
    if (existing > 0) label += " · 升级加密格式，旧客户端将拒绝该金库";
  }
  return label;
}

function startCredential({ create, rp, id, challenge, account, userId = [4, 5, 6], displayName = "Other synthetic account", abortAfter }) {
  const decode = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const controller = new AbortController();
  window.managementResult = null;
  window.managementError = null;
  const options = create ? {
    rp: { id: rp, name: "Synthetic management acceptance" },
    user: { id: new Uint8Array(userId), name: account, displayName },
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
  dismissPopup, reconnect, eventually, input, observe, phase, conditionalSibling,
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
  const verified = new Map();
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
    input([...factors, { click_label: passkeyChoiceLabel({ rp, title: rp + " · " + name, username: name, credentialId: registration.id }) }]);
    await focusPage();
    const state = await waitResult();
    assert(!state.error && state.result?.instance, "Managed credential assertion rejected");
    checkSignature(registration, state.result.json, challenge);
    const registrationInfo = verified.get(registration.id);
    if (verifier && registrationInfo) {
      const checked = await verifier.verifyAuthenticationResponse({
        response: state.result.json, expectedChallenge: challenge, expectedOrigin: origin,
        expectedRPID: rp, credential: registrationInfo.registrationInfo.credential,
        requireUserVerification: true,
      });
      assert.equal(checked.verified, true, "Independent verifier rejected managed credential");
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
    const checked = await verifier.verifyRegistrationResponse({
      response: second, expectedChallenge: challenge, expectedOrigin: origin,
      expectedRPID: rp, requireUserVerification: true,
    });
    assert.equal(checked.verified, true, "Independent verifier rejected second registration");
    verified.set(second.id, checked);
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
  // passkey-remove always needs the native owner review, even outside quick
  // fill. Both decisions must be the exact fixed controls; only approval is
  // clicked, and nothing may commit before that physical click.
  const approveRemove = "批准删除 Passkey", rejectRemove = "拒绝删除 Passkey";
  const nativeRemove = async before => {
    const controls = input([], true, { inspect: true }).controls || {};
    for (const label of [approveRemove, rejectRemove]) {
      assert(controls[label]?.present === true && controls[label]?.showing === true,
        "Exact native " + label + " control missing");
    }
    assert.equal(observe().snapshot_digest, before.snapshot_digest,
      "Passkey removed before native owner approval");
    input([{ click_label: approveRemove }]);
    await eventually(() => {
      const after = input([], true, { inspect: true }).controls || {};
      return !after[approveRemove]?.showing && !after[rejectRemove]?.showing &&
        observe().snapshot_digest !== before.snapshot_digest;
    }, "Approved Passkey removal did not persist", 30000);
  };
  let popup;
  phase("passkey-management:add-same-login-credential");
  const beforeSibling = observe();
  await dismissPopup();
  const siblingChallenge = Buffer.from("synthetic-managed-add-same-login").toString("base64url");
  await pageEval(startCredential, {
    create: true, rp, challenge: siblingChallenge, account: "passkey-test",
    userId: [1, 2, 3], displayName: "Synthetic user",
  });
  await inlineClick("保存到 Locklark");
  input([...factors, {
    click_label: passkeyChoiceLabel({
      create: true, rp, title: firstTitle, username: "passkey-test",
      credentialId: first.id, existing: 1,
    }),
  }]);
  await focusPage();
  const siblingCreated = await waitResult();
  assert(!siblingCreated.error && siblingCreated.result?.instance,
    "Second credential for the existing login was rejected");
  const sibling = siblingCreated.result.json;
  assert.notEqual(sibling.id, first.id, "Sibling credential reused the first credential ID");
  const siblingClient = JSON.parse(Buffer.from(sibling.response.clientDataJSON, "base64url"));
  assert.equal(siblingClient.origin, origin);
  assert.equal(siblingClient.challenge, siblingChallenge);
  assert.equal(siblingClient.type, "webauthn.create");
  assert.equal(sibling.response.publicKeyAlgorithm, -7, "Sibling must use ES256");
  assert(sibling.response.publicKey, "Sibling public key metadata required");
  if (verifier) {
    const checked = await verifier.verifyRegistrationResponse({
      response: sibling, expectedChallenge: siblingChallenge, expectedOrigin: origin,
      expectedRPID: rp, requireUserVerification: true,
    });
    assert.equal(checked.verified, true, "Independent verifier rejected sibling registration");
    verified.set(sibling.id, checked);
  }
  const siblingParents = observe().rows.filter(item => item.title === firstTitle);
  assert.equal(siblingParents.length, 1, "Sibling registration created a second login record");
  assert.equal(siblingParents[0].id, firstID, "Sibling registration changed the first parent ID");
  assert.equal(beforeSibling.rows.filter(item => item.title === firstTitle).length, 1,
    "First parent was not unique before sibling registration");
  phase("passkey-management:select-second-sibling");
  phase("passkey-management:select-second-sibling:before-preselection-placeholder");
  popup = await openFirst();
  await eventually(async () => await popup.count("#passkey-select option") === 3,
    "Two sibling Passkeys must list a placeholder and both entries");
  phase("passkey-management:select-second-sibling:preselection-placeholder");
  assert.equal(await popup.value("#passkey-select"), "",
    "Popup automatically selected the first sibling");
  assert.equal(await popup.text("#passkey-rp"), "-", "Unselected RP metadata must stay blank");
  assert.equal(await popup.text("#passkey-username"), "-",
    "Unselected account metadata must stay blank");
  assert.equal(await popup.text("#passkey-credential-hint"), "",
    "Unselected credential hint must stay blank");
  assert.equal(await popup.visible("#passkey-remove"), false,
    "Removal control must stay hidden until an explicit sibling choice");
  await popup.selectOption("#passkey-select", sibling.id, step =>
    phase("passkey-management:select-second-sibling:" + step));
  await eventually(async () => await popup.value("#passkey-select") === sibling.id,
    "Physical popup selection did not choose the exact second sibling");
  phase("passkey-management:select-second-sibling:post-selected-hint");
  assert.equal(await popup.text("#passkey-credential-hint"), passkeyPopupHint(sibling.id),
    "Popup showed the first sibling hint after selecting the second");
  assert.equal(await popup.text("#passkey-rp"), rp, "Selected second sibling RP metadata mismatch");
  assert.equal(await popup.text("#passkey-username"), "passkey-test",
    "Selected second sibling account metadata mismatch");
  phase("passkey-management:second-sibling-signature");
  await dismissPopup();
  const siblingGetChallenge = Buffer.from("synthetic-managed-sibling-get").toString("base64url");
  await pageEval(startCredential, { create: false, rp, id: sibling.id, challenge: siblingGetChallenge });
  await inlineClick("使用 Locklark 登录");
  input([...factors, {
    click_label: passkeyChoiceLabel({
      rp, title: firstTitle, username: "passkey-test", credentialId: sibling.id,
    }),
  }]);
  await focusPage();
  const siblingSigned = await waitResult();
  assert(!siblingSigned.error && siblingSigned.result?.instance,
    "Second sibling assertion was rejected");
  assert.equal(siblingSigned.result.json.id, sibling.id, "First sibling signed the request");
  checkSignature(sibling, siblingSigned.result.json, siblingGetChallenge);
  if (verifier && verified.has(sibling.id)) {
    const checked = await verifier.verifyAuthenticationResponse({
      response: siblingSigned.result.json, expectedChallenge: siblingGetChallenge,
      expectedOrigin: origin, expectedRPID: rp,
      credential: verified.get(sibling.id).registrationInfo.credential,
      requireUserVerification: true,
    });
    assert.equal(checked.verified, true, "Independent verifier rejected second sibling");
  }
  if (conditionalSibling && process.env.LOCKLARK_TEST_PASSKEY_CONDITIONAL === "1") {
    phase("passkey-management:conditional-two-siblings");
    await conditionalSibling({ first, second: sibling });
  }
  phase("passkey-management:delete-second-sibling");
  popup = await keys();
  await eventually(async () => await popup.count(row(firstID)) === 1,
    "First account missing before sibling removal");
  await popup.click(row(firstID));
  await eventually(async () => await popup.visible("#passkey-detail"),
    "First Passkey detail unavailable before sibling removal");
  await eventually(async () => await popup.count("#passkey-select option") === 3,
    "Sibling selector missing before removal");
  await popup.selectOption("#passkey-select", sibling.id);
  await popup.click("#passkey-remove");
  await eventually(async () => await popup.visible("#passkey-remove-confirm"),
    "Sibling removal confirmation missing");
  const beforeSiblingRemoval = observe();
  await popup.click("#passkey-remove-confirm");
  await nativeRemove(beforeSiblingRemoval);
  // Only a fresh popup is trusted after the removal: refetch the affected login.
  popup = await keys();
  await eventually(async () => await popup.count(row(firstID)) === 1,
    "First account missing after sibling removal");
  await popup.click(row(firstID));
  await eventually(async () => await popup.visible("#passkey-detail"),
    "Removing the second sibling did not leave exactly the first credential", 30000);
  assert.equal(await popup.count("#passkey-select option"), 0,
    "Removing the second sibling did not leave exactly the first credential");
  assert.equal(await popup.text("#passkey-credential-hint"), passkeyPopupHint(first.id),
    "First credential hint did not remain after sibling removal");
  phase("passkey-management:deleted-sibling-unavailable");
  assert(observe().rows.some(item => item.id === secondID),
    "Sibling removal deleted the other account");
  await dismissPopup();
  await pageEval(startCredential, { create: false, rp, id: sibling.id,
    challenge: Buffer.from("synthetic-deleted-sibling-get").toString("base64url"), abortAfter: 2000 });
  await inlineClick("使用 Locklark 登录");
  const removedSibling = await waitResult();
  assert(!removedSibling.result && removedSibling.error,
    "Deleted sibling credential produced an assertion result");
  const siblingControls = input([], true, { inspect: true }).controls || {};
  assert(!siblingControls[passkeyChoiceLabel({
    rp, title: firstTitle, username: "passkey-test", credentialId: sibling.id,
  })]?.showing, "Deleted sibling remained an approvable native choice");
  phase("passkey-management:first-after-sibling-removal");
  await dismissPopup();
  const firstAfterChallenge = Buffer.from("synthetic-managed-first-after-sibling").toString("base64url");
  await pageEval(startCredential, { create: false, rp, id: first.id, challenge: firstAfterChallenge });
  await inlineClick("使用 Locklark 登录");
  input([...factors, {
    click_label: passkeyChoiceLabel({
      rp, title: firstTitle, username: "passkey-test", credentialId: first.id,
    }),
  }]);
  await focusPage();
  const firstAfter = await waitResult();
  assert(!firstAfter.error && firstAfter.result?.instance,
    "First credential assertion was rejected after sibling removal");
  assert.equal(firstAfter.result.json.id, first.id, "Removed sibling signed instead of first credential");
  checkSignature(first, firstAfter.result.json, firstAfterChallenge);
  await get(second, account);
  phase("passkey-management:list-two-accounts");
  popup = await keys();
  await eventually(async () => await popup.count(row(firstID)) === 1 && await popup.count(row(secondID)) === 1,
    "Both accounts must appear in server-filtered Passkey list");
  await popup.click(row(firstID));
  await eventually(async () => await popup.visible("#passkey-detail"), "First Passkey detail unavailable");
  phase("passkey-management:preservation-edit");
  await popup.click("#detail-edit");
  await eventually(async () => await popup.visible("#editor-view"), "Passkey login editor did not open");
  for (const [name, value] of [["password", fixture.Value], ["notes", fixture.UpdateValue]]) {
    phase("passkey-management:preservation-edit-" + name);
    const selector = '#editor-fields ' + (name === "notes" ? "textarea" : "input") + '[data-field="' + name + '"]';
    await eventually(async () => await popup.visible(selector), "Passkey login editor field unavailable");
    await popup.click(selector);
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
  const beforeFinalRemoval = observe();
  await popup.click("#passkey-remove-confirm");
  await nativeRemove(beforeFinalRemoval);
  assert(observe().rows.some(item => item.id === firstID), "Removing a Passkey deleted its login");
  // The final removal must leave the login and its password/notes intact, so
  // refetch that exact login from a fresh popup before revealing the fields.
  popup = await keys();
  await popup.click('#filter-tabs [data-filter="all"]');
  await eventually(async () => await popup.count(row(firstID)) === 1,
    "Passkey removal did not persist");
  await popup.click(row(firstID));
  await eventually(async () => !(await popup.visible("#passkey-detail")) &&
    await popup.visible('[data-field-id="password"]'), "Passkey removal did not persist", 30000);
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
  assert(!controls[passkeyChoiceLabel({ rp, title: rp + " · passkey-test", username: "passkey-test", credentialId: first.id })]?.showing,
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

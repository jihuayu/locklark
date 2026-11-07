// Real Chromium/Edge coexistence acceptance against an explicitly SOFTWARE
// other WebAuthn provider: a CDP virtual ctap2/USB authenticator. No hardware,
// no Windows Hello, no extension messages and no product test hooks. The only
// product interaction is the caller's physical closed-shadow fallback click.
import assert from "node:assert/strict";
import {
  createHash, createPublicKey, randomBytes, verify,
} from "node:crypto";
import { createRequire } from "node:module";
import { verifyRegistrationResponse } from "./browser_firefox_passkey_acceptance.mjs";

const WAIT_MS = 20000;
const FALLBACK_LABEL = "使用其他验证器";
const decode = value => Buffer.from(value, "base64url");
const encode = value => Buffer.from(value).toString("base64url");
const sha256 = value => createHash("sha256").update(value).digest();
const digest = value => sha256(JSON.stringify(value));

export function verifyAssertion({
  response, credentialId, challenge, origin, rp, publicKey,
}) {
  assert(response?.type === "public-key" &&
    response.id === credentialId && response.rawId === credentialId,
    "Other-provider assertion credential ID mismatch");
  const clientRaw = decode(response.response?.clientDataJSON || "");
  let client;
  try { client = JSON.parse(clientRaw.toString("utf8")); }
  catch { throw Error("Other-provider assertion client data invalid"); }
  assert(client.type === "webauthn.get",
    "Other-provider assertion ceremony type mismatch");
  assert(client.challenge === challenge,
    "Other-provider assertion challenge mismatch");
  assert(client.origin === origin, "Other-provider assertion origin mismatch");
  const auth = decode(response.response?.authenticatorData || "");
  assert(auth.length >= 37, "Other-provider assertion data truncated");
  assert(auth.subarray(0, 32).equals(sha256(rp)),
    "Other-provider assertion RP ID hash mismatch");
  assert((auth[32] & 0x05) === 0x05,
    "Other-provider assertion requires UP and UV");
  assert(verify(
    "sha256",
    Buffer.concat([auth, sha256(clientRaw)]),
    publicKey,
    decode(response.response?.signature || ""),
  ), "Other-provider assertion signature verification failed");
  return {
    userHandle: response.response?.userHandle
      ? decode(response.response.userHandle) : null,
  };
}

function pageStartCreate({ rp, challenge, userId }) {
  const bytes = value => Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/")),
    character => character.charCodeAt(0),
  );
  window.__otherProviderCreate = null;
  window.__otherProviderCreateError = null;
  navigator.credentials.create({
    publicKey: {
      rp: { id: rp, name: "Synthetic other provider" },
      user: {
        id: bytes(userId),
        name: "other-provider-test",
        displayName: "Synthetic other provider",
      },
      challenge: bytes(challenge),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
        residentKey: "required",
        userVerification: "required",
      },
      attestation: "none",
    },
  }).then(
    credential => {
      window.__otherProviderCreate = {
        json: credential.toJSON(),
        publicKey: Array.from(new Uint8Array(credential.response.getPublicKey())),
        algorithm: credential.response.getPublicKeyAlgorithm(),
        instance: credential instanceof PublicKeyCredential,
      };
    },
    error => { window.__otherProviderCreateError = error?.name || "error"; },
  );
}

function pageStartGet({ rp, challenge, credentialId }) {
  const bytes = value => Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/")),
    character => character.charCodeAt(0),
  );
  window.__otherProviderGet = null;
  window.__otherProviderGetError = null;
  navigator.credentials.get({
    publicKey: {
      rpId: rp,
      challenge: bytes(challenge),
      allowCredentials: [{ type: "public-key", id: bytes(credentialId) }],
      userVerification: "required",
    },
  }).then(
    credential => {
      window.__otherProviderGet = {
        json: credential.toJSON(),
        instance: credential instanceof PublicKeyCredential,
        response: credential.response instanceof AuthenticatorAssertionResponse,
      };
    },
    error => { window.__otherProviderGetError = error?.name || "error"; },
  );
}

const readCreate = () => ({
  value: window.__otherProviderCreate,
  error: window.__otherProviderCreateError,
});
const readGet = () => ({
  value: window.__otherProviderGet,
  error: window.__otherProviderGetError,
});
const getPending = () =>
  !window.__otherProviderGet && !window.__otherProviderGetError;

export async function acceptOtherProvider({
  page,
  cdp,
  origin,
  first,
  inlineClick,
  eventually,
  observe,
  phase,
}) {
  assert(page && typeof page.evaluate === "function", "Browser page required");
  assert(cdp && typeof cdp.send === "function", "Browser CDP session required");
  assert(typeof first?.id === "string" && first.id.length > 0,
    "Existing Locklark credential required");
  const rp = new URL(origin).hostname;
  assert(rp, "Controlled relying-party origin required");
  const createChallenge = randomBytes(32).toString("base64url");
  const getChallenge = randomBytes(32).toString("base64url");
  const userId = randomBytes(16).toString("base64url");
  let enabled = false;
  let authenticatorId = null;
  const command = async (method, params) => {
    // Unsupported/absent CDP support must fail the selected acceptance rather
    // than silently skip the other-provider case.
    try { return await cdp.send(method, params); }
    catch { throw Error("WebAuthn CDP protocol unavailable"); }
  };
  try {
    phase("other-provider:virtual-authenticator");
    await command("WebAuthn.enable", { enableUI: false });
    enabled = true;
    ({ authenticatorId } = await command("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "usb",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    }));
    assert(authenticatorId, "WebAuthn CDP protocol unavailable");
    const before = observe();
    phase("other-provider:cross-platform-create");
    await page.bringToFront();
    await page.evaluate(pageStartCreate, {
      rp, challenge: createChallenge, userId,
    });
    await eventually(async () => {
      const state = await page.evaluate(readCreate);
      return !!(state.value || state.error);
    }, "Other-provider registration did not complete", WAIT_MS);
    const createState = await page.evaluate(readCreate);
    assert(!createState.error, "Other-provider registration failed");
    const created = createState.value;
    assert(created?.instance && created.algorithm === -7 &&
      Array.isArray(created.publicKey) && created.publicKey.length > 0 &&
      created.json?.response, "Other-provider registration contract");
    assert(created.json.id !== first.id,
      "Other provider did not create an independent credential");
    phase("other-provider:independent-registration");
    const publicKeyBytes = Buffer.from(created.publicKey);
    verifyRegistrationResponse({
      response: {
        ...created.json,
        rawId: created.json.rawId || created.json.id,
        response: { ...created.json.response, publicKey: encode(publicKeyBytes) },
      },
      expectedChallenge: createChallenge,
      expectedOrigin: origin,
      expectedRPID: rp,
      requireUserVerification: true,
    });
    const publicKey = createPublicKey({
      key: publicKeyBytes, format: "der", type: "spki",
    });
    assert(publicKey.asymmetricKeyType === "ec",
      "Other-provider public key must be EC");
    assert(publicKey.asymmetricKeyDetails?.namedCurve === "prime256v1",
      "Other-provider public key must be P-256");
    let server = null;
    let serverCredential = null;
    if (process.env.LOCKLARK_TEST_WEBAUTHN_SERVER) {
      server = createRequire(import.meta.url)(
        process.env.LOCKLARK_TEST_WEBAUTHN_SERVER,
      );
      const checked = await server.verifyRegistrationResponse({
        response: created.json,
        expectedChallenge: createChallenge,
        expectedOrigin: origin,
        expectedRPID: rp,
        requireUserVerification: true,
      });
      assert.equal(checked.verified, true,
        "Independent WebAuthn registration rejected");
      serverCredential = checked.registrationInfo?.credential;
      assert(serverCredential, "Independent WebAuthn credential missing");
    }
    phase("other-provider:locklark-fallback-prompt");
    await page.bringToFront();
    await page.evaluate(pageStartGet, {
      rp, challenge: getChallenge, credentialId: created.json.id,
    });
    assert.equal(await page.evaluate(getPending), true,
      "Passkey request bypassed explicit other-authenticator selection");
    await inlineClick(FALLBACK_LABEL);
    await eventually(async () => {
      const state = await page.evaluate(readGet);
      return !!(state.value || state.error);
    }, "Other-provider assertion did not complete", WAIT_MS);
    const getState = await page.evaluate(readGet);
    assert(!getState.error, "Other-provider assertion failed");
    const signed = getState.value;
    assert(signed?.instance && signed.response && signed.json?.response,
      "Other-provider assertion contract");
    phase("other-provider:independent-assertion");
    const assertion = verifyAssertion({
      response: signed.json,
      credentialId: created.json.id,
      challenge: getChallenge,
      origin,
      rp,
      publicKey,
    });
    // With an explicit allowCredentials list a valid native authenticator
    // may omit userHandle. When present it must still identify our account.
    if (assertion.userHandle)
      assert(assertion.userHandle.equals(decode(userId)),
        "Other-provider resident user handle mismatch");
    if (server) {
      const checked = await server.verifyAuthenticationResponse({
        response: signed.json,
        expectedChallenge: getChallenge,
        expectedOrigin: origin,
        expectedRPID: rp,
        credential: serverCredential,
        requireUserVerification: true,
      });
      assert.equal(checked.verified, true,
        "Independent WebAuthn authentication rejected");
    }
    phase("other-provider:vault-unchanged");
    const after = observe();
    assert(after.snapshot_digest === before.snapshot_digest,
      "Other-provider coexistence changed the vault snapshot");
    assert(digest(after.rows).equals(digest(before.rows)),
      "Other-provider coexistence changed login metadata");
    assert(digest(after.save_events).equals(digest(before.save_events)),
      "Other-provider coexistence changed save history");
    assert(digest(after.otp_events).equals(digest(before.otp_events)),
      "Other-provider coexistence changed OTP history");
    console.log(
      "PASS: real Chromium/Edge other-provider coexistence with a software virtual authenticator, explicit Locklark fallback, independently verified assertion and unchanged vault",
    );
  } finally {
    if (authenticatorId) {
      await cdp.send("WebAuthn.removeVirtualAuthenticator", {
        authenticatorId,
      }).catch(() => {});
    }
    if (enabled) await cdp.send("WebAuthn.disable").catch(() => {});
  }
}

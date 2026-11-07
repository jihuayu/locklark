// External Firefox Passkey acceptance for the existing real geckodriver/X11
// driver. No product hooks, no privileged extension messaging, no CDP: the
// relying party is the controlled HTTPS page and the closed-shadow extension
// panel is only *observed* through the already-used WebDriver chrome context,
// then clicked with real XTest pointer events by the caller.
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { createRequire } from "node:module";
import { fixtureCanaries } from "./browser_save_acceptance.mjs";
import { acceptPasskeyManagement } from "./browser_passkey_management_acceptance.mjs";

export const PASSKEY_CONTRACT = Object.freeze({
  gate: "LOCKLARK_TEST_FIREFOX_PASSKEY=1",
  rpID: "login.locklark.test",
  userName: "passkey-test",
  inlineButtons: Object.freeze([
    "保存到 Locklark",
    "使用 Locklark 登录",
    "使用其他验证器",
  ]),
  nativeControls: Object.freeze({
    verifyPassword: "验证主密码",
    verifySecret: "验证 Secret Key",
    create: "创建新登录并保存 Passkey",
    get: "登录：login.locklark.test · passkey-test · passkey-test",
  }),
  driverHooks: Object.freeze([
    "origin",
    "fixture",
    "phase",
    "eventually",
    "input",
    "pageEval",
    "chromeEval",
    "clickScreen",
    "locateButtons",
    "viewportOrigin",
    "dismissPopup",
    "reconnect",
    "pause",
  ]),
});

// Two independent read-only probes locate the closed-shadow panel; every click
// stays a real XTest pointer event. Strategy 1 needs an in-process tab (Xray
// content window). Strategy 2 needs no content window at all: it combines the
// chrome browser-element rect on screen with BiDi-located nodes measured via
// remote references, so out-of-process (Fission) tabs stay inspectable.
const CHROME_CONTENT_SOURCE =
  "const label=arguments[0];" +
  'if(typeof gBrowser==="undefined"||!gBrowser.selectedBrowser)return {found:false,reason:"no-gbrowser"};' +
  "const content=gBrowser.selectedBrowser.contentWindow;" +
  'if(!content||!content.document)return {found:false,reason:"no-content-window"};' +
  'const find=(root)=>{for(const element of root.querySelectorAll("*")){' +
  'if(element.localName==="button"&&(element.textContent||"").trim()===label)return element;' +
  "const shadow=element.openOrClosedShadowRoot||element.shadowRoot;" +
  "if(shadow){const found=find(shadow);if(found)return found;}}return null;};" +
  "const found=find(content.document);" +
  'if(!found)return {found:false,reason:"no-shadow-button"};' +
  "const rect=found.getBoundingClientRect();" +
  "return {found:true,disabled:found.disabled===true,width:rect.width,height:rect.height," +
  "x:content.mozInnerScreenX+rect.left+rect.width/2,y:content.mozInnerScreenY+rect.top+rect.height/2};";
export const CHROME_VIEWPORT_SOURCE =
  'const b=(typeof gBrowser!=="undefined"&&gBrowser.selectedBrowser)||document.querySelector("browser[type=content-primary],browser");' +
  'if(!b)return {found:false,reason:"no-browser"};' +
  "const rect=b.getBoundingClientRect();" +
  'if(!(rect.width>0&&rect.height>0))return {found:false,reason:"no-browser-rect"};' +
  "return {found:true,x:window.mozInnerScreenX+rect.left,y:window.mozInnerScreenY+rect.top};";

const sha256 = (value) => createHash("sha256").update(value).digest();

function fromBase64URL(value, description) {
  assert.equal(typeof value, "string", description + " must be base64url text");
  assert(
    /^[A-Za-z0-9_-]*$/.test(value) && value.length % 4 !== 1,
    description + " is not unpadded base64url",
  );
  const bytes = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  assert.equal(bytes.toString("base64url"), value, description + " is not canonical");
  return bytes;
}

function cborDecode(buffer, cursor = { at: 0 }) {
  const read = (size) => {
    const value = buffer.subarray(cursor.at, cursor.at + size);
    assert.equal(value.length, size, "Truncated CBOR item");
    cursor.at += size;
    return value;
  };
  const byte = read(1)[0];
  const major = byte >> 5;
  const info = byte & 31;
  const length = () => {
    if (info < 24) return info;
    if (info === 24) return read(1)[0];
    if (info === 25) return read(2).readUInt16BE(0);
    if (info === 26) return read(4).readUInt32BE(0);
    throw Error("Unsupported CBOR length encoding");
  };
  if (major === 0) return length();
  if (major === 1) return -1 - length();
  if (major === 2) return Buffer.from(read(length()));
  if (major === 3) return read(length()).toString("utf8");
  if (major === 5) {
    const map = {};
    const count = length();
    assert(count <= 32, "Unsupported CBOR map size");
    for (let index = 0; index < count; index++) {
      const key = cborDecode(buffer, cursor);
      map[typeof key === "string" ? key : String(key)] = cborDecode(buffer, cursor);
    }
    return map;
  }
  if (major === 7 && info === 20) return false;
  if (major === 7 && info === 21) return true;
  if (major === 7 && info === 22) return null;
  throw Error("Unsupported CBOR item in WebAuthn data");
}

// ES256 SPKI prefix: id-ecPublicKey + prime256v1 + uncompressed point.
const P256_SPKI_PREFIX = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004",
  "hex",
);

function coseToPublicKey(cose) {
  assert.equal(cose["1"], 2, "COSE kty must be EC2");
  assert.equal(cose["3"], -7, "COSE alg must be ES256");
  assert.equal(cose["-1"], 1, "COSE curve must be P-256");
  const x = cose["-2"];
  const y = cose["-3"];
  assert(
    Buffer.isBuffer(x) && Buffer.isBuffer(y) && x.length === 32 && y.length === 32,
    "COSE EC2 coordinates must be 32 bytes",
  );
  return createPublicKey({
    key: Buffer.concat([P256_SPKI_PREFIX, x, y]),
    format: "der",
    type: "spki",
  });
}
// Independent relying-party verification. Mirrors the Chromium helper's checks
// (client data, RP ID hash, flags, credential ID, ES256 signature) without any
// browser automation channel. LOCKLARK_TEST_WEBAUTHN_SERVER may name an
// independent WebAuthn server module exactly as in the Chromium acceptance.
function verifiedClientData(response, { type, challenge, origin }) {
  const raw = fromBase64URL(
    response?.response?.clientDataJSON,
    "clientDataJSON",
  );
  const client = JSON.parse(raw.toString("utf8"));
  assert.equal(client.type, type, "Unexpected WebAuthn ceremony type");
  assert.equal(client.challenge, challenge, "Challenge mismatch");
  assert.equal(client.origin, origin, "Origin mismatch");
  return raw;
}

export function verifyRegistrationResponse({
  response,
  expectedChallenge,
  expectedOrigin,
  expectedRPID,
  requireUserVerification = true,
}) {
  verifiedClientData(response, {
    type: "webauthn.create",
    challenge: expectedChallenge,
    origin: expectedOrigin,
  });
  assert.equal(response.type, "public-key", "Credential type must be public-key");
  const attestation = cborDecode(
    fromBase64URL(response.response?.attestationObject, "attestationObject"),
  );
  assert.equal(attestation.fmt, "none", "Unexpected attestation format");
  assert.deepEqual(
    Object.keys(attestation.attStmt || {}),
    [],
    "none attestation statement must be empty",
  );
  const auth = attestation.authData;
  assert(Buffer.isBuffer(auth) && auth.length >= 55, "Truncated authenticator data");
  assert.deepEqual(auth.subarray(0, 32), sha256(expectedRPID), "RP ID hash mismatch");
  const flags = auth[32];
  assert.equal(flags & 0x01, 0x01, "User presence flag missing");
  if (requireUserVerification)
    assert.equal(flags & 0x04, 0x04, "User verification flag missing");
  assert.equal(flags & 0x40, 0x40, "Attested credential data missing");
  const size = auth.readUInt16BE(53);
  assert(size > 0 && size <= 64 && auth.length > 55 + size, "Credential ID size");
  const credentialId = auth.subarray(55, 55 + size);
  assert.deepEqual(
    credentialId,
    fromBase64URL(response.rawId, "rawId"),
    "Credential ID mismatch",
  );
  assert.equal(response.id, credentialId.toString("base64url"), "id/rawId mismatch");
  const publicKey = coseToPublicKey(cborDecode(auth, { at: 55 + size }));
  const hostKey = response.response.publicKey
    ? fromBase64URL(response.response.publicKey, "publicKey")
    : null;
  if (hostKey)
    assert.deepEqual(
      hostKey,
      publicKey.export({ format: "der", type: "spki" }),
      "Host public key disagrees with attested credential data",
    );
  return { verified: true, credentialId, publicKey };
}

export function verifyAuthenticationResponse({
  response,
  expectedChallenge,
  expectedOrigin,
  expectedRPID,
  publicKey,
  requireUserVerification = true,
}) {
  const clientRaw = verifiedClientData(response, {
    type: "webauthn.get",
    challenge: expectedChallenge,
    origin: expectedOrigin,
  });
  const auth = fromBase64URL(
    response.response?.authenticatorData,
    "authenticatorData",
  );
  assert(auth.length >= 37, "Truncated assertion authenticator data");
  assert.deepEqual(auth.subarray(0, 32), sha256(expectedRPID), "RP ID hash mismatch");
  const flags = auth[32];
  assert.equal(flags & 0x01, 0x01, "Assertion user presence missing");
  if (requireUserVerification)
    assert.equal(flags & 0x04, 0x04, "Assertion user verification missing");
  const signature = fromBase64URL(response.response?.signature, "signature");
  assert(
    verify(
      "sha256",
      Buffer.concat([auth, sha256(clientRaw)]),
      publicKey,
      signature,
    ),
    "Relying-party signature verification failed",
  );
  const userHandle = response.response?.userHandle;
  return {
    verified: true,
    userHandle: userHandle ? fromBase64URL(userHandle, "userHandle") : null,
  };
}

function externalServer() {
  const module = process.env.LOCKLARK_TEST_WEBAUTHN_SERVER;
  if (!module) return null;
  const require = createRequire(import.meta.url);
  return require(module);
}

function startCreateInPage({ rp, challenge }) {
  const decode = (value) =>
    Uint8Array.from(
      atob(value.replace(/-/g, "+").replace(/_/g, "/")),
      (character) => character.charCodeAt(0),
    );
  window.passkeyResult = null;
  window.passkeyError = null;
  navigator.credentials
    .create({
      publicKey: {
        rp: { id: rp, name: "Synthetic Firefox acceptance" },
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
      (credential) => {
        window.passkeyResult = {
          json: credential.toJSON(),
          instance: credential instanceof PublicKeyCredential,
          response: credential.response instanceof AuthenticatorAttestationResponse,
          algorithm: credential.response.getPublicKeyAlgorithm(),
        };
      },
      (error) => {
        window.passkeyError = error?.name || "error";
      },
    );
}

function startGetInPage({ id, rp, challenge }) {
  const decode = (value) =>
    Uint8Array.from(
      atob(value.replace(/-/g, "+").replace(/_/g, "/")),
      (character) => character.charCodeAt(0),
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
      (credential) => {
        window.passkeyResult = {
          json: credential.toJSON(),
          instance: credential instanceof PublicKeyCredential,
          response: credential.response instanceof AuthenticatorAssertionResponse,
        };
      },
      (error) => {
        window.passkeyError = error?.name || "error";
      },
    );
}
function startCancelInPage() {
  window.passkeyCancel = null;
  const controller = new AbortController();
  navigator.credentials
    .get({
      signal: controller.signal,
      publicKey: { challenge: new Uint8Array(32) },
    })
    .then(
      () => {
        window.passkeyCancel = "unexpected";
      },
      (error) => {
        window.passkeyCancel = error?.name || "error";
      },
    );
  controller.abort();
}

function startFallbackInPage({ rp, challenge }) {
  const decode = (value) =>
    Uint8Array.from(
      atob(value.replace(/-/g, "+").replace(/_/g, "/")),
      (character) => character.charCodeAt(0),
    );
  const controller = new AbortController();
  window.passkeyResult = null;
  window.passkeyFallback = "pending";
  window.passkeyFallbackAbort = () => controller.abort();
  navigator.credentials
    .get({
      signal: controller.signal,
      publicKey: {
        rpId: rp,
        challenge: decode(challenge),
        userVerification: "discouraged",
        timeout: 20000,
      },
    })
    .then(
      () => {
        window.passkeyFallback = "resolved";
      },
      (error) => {
        window.passkeyFallback = "rejected:" + (error?.name || "error");
      },
    );
}

function readResultInPage() {
  return { result: window.passkeyResult, error: window.passkeyError };
}

function readCancelInPage() {
  return window.passkeyCancel;
}

function readFallbackInPage() {
  return { state: window.passkeyFallback, result: window.passkeyResult };
}

function abortFallbackInPage() {
  window.passkeyFallbackAbort();
  return true;
}

function pageLeakInPage(canaries) {
  const text = document.documentElement.outerHTML;
  return canaries.filter((value) => text.includes(value));
}

export async function acceptFirefoxPasskey(driver) {
  for (const hook of PASSKEY_CONTRACT.driverHooks)
    assert.notEqual(driver[hook], undefined, "Passkey driver hook missing: " + hook);
  const {
    origin,
    fixture,
    phase,
    eventually,
    input,
    pageEval,
    chromeEval,
    clickScreen,
    locateButtons,
    viewportOrigin,
    dismissPopup,
    reconnect,
    pause,
  } = driver;
  const rp = new URL(origin).hostname;
  assert.equal(
    rp,
    PASSKEY_CONTRACT.rpID,
    "Allowlisted native passkey labels require the synthetic fixture RP ID",
  );
  const canaries = fixtureCanaries(fixture);
  const safeName = (value) =>
    String(value ?? "").replace(/[^A-Za-z]/g, "").slice(0, 32) || "unknown";
  const probeInline = async (label) => {
    const strategies = [];
    try {
      const direct = await chromeEval(CHROME_CONTENT_SOURCE, [label]);
      if (direct?.found === true)
        return { found: true, strategy: "chrome-content", ...direct };
      strategies.push("chrome-content:" + (direct?.reason || "not-found"));
    } catch {
      strategies.push("chrome-content:error");
    }
    try {
      const origin = await viewportOrigin();
      if (origin?.found === true) {
        const nodes = await locateButtons(label);
        const button = nodes.find((node) => node.text === label);
        if (button)
          return {
            found: true,
            strategy: "chrome-viewport+bidi-locate",
            disabled: button.disabled,
            width: button.width,
            height: button.height,
            x: origin.x + button.left + button.width / 2,
            y: origin.y + button.top + button.height / 2,
          };
        strategies.push("bidi-locate:not-found:" + nodes.length);
      } else strategies.push("chrome-viewport:" + (origin?.reason || "not-found"));
    } catch {
      strategies.push("bidi-locate:error");
    }
    return { found: false, strategies };
  };
  const inlinePoint = probeInline;
  const clickInline = async (label) => {
    let found;
    try {
      await eventually(
        async () => {
          found = await inlinePoint(label);
          return found?.found === true && found.disabled === false;
        },
        "PasskeyFailure:inline-unavailable:" + label,
        20000,
      );
    } catch {
      console.error(
        "Passkey inline probe: " +
          JSON.stringify({
            control: label,
            strategies: found?.strategies || ["not-probed"],
          }),
      );
      throw Error("PasskeyFailure:inline-unavailable:" + label);
    }
    assert(
      found.width > 8 && found.height > 8 && found.x > 0 && found.y > 0,
      "PasskeyFailure:inline-geometry:" + label,
    );
    clickScreen(found.x, found.y);
    return found.strategy;
  };
  const inlineAbsent = async (label) => {
    const found = await inlinePoint(label);
    return found?.found !== true;
  };
  const verifyFactors = [
    { wait_label: "验证主密码" },
    { click_label: "验证主密码" },
    { text: fixture.Password },
    { click_label: "验证 Secret Key" },
    { text: fixture.Secret },
  ];
  const nativeLabel = (control) => {
    assert(control in PASSKEY_CONTRACT.nativeControls, "Unknown native control");
    return PASSKEY_CONTRACT.nativeControls[control];
  };
  phase("firefox-passkey-connect");
  await reconnect();
  await dismissPopup();
  await pause(300);
  phase("firefox-passkey-create:page-request");
  const challenge = Buffer.from(
    "synthetic-firefox-create-challenge-01",
  ).toString("base64url");
  await pageEval(startCreateInPage, { rp, challenge });
  phase("firefox-passkey-create:inline");
  await clickInline("保存到 Locklark");
  phase("firefox-passkey-create:native-factors");
  input([...verifyFactors, { click_label: nativeLabel("create") }]);
  phase("firefox-passkey-create:result");
  await eventually(
    async () => {
      const state = await pageEval(readResultInPage);
      return !!(state.result || state.error);
    },
    "Firefox passkey creation did not complete",
    30000,
  );
  const created = await pageEval(readResultInPage);
  assert(
    !created.error,
    "PasskeyFailure:create-rejected:" + safeName(created.error),
  );
  assert(
    created.result?.instance && created.result.response,
    "PublicKeyCredential/AuthenticatorAttestationResponse contract",
  );
  assert.equal(created.result.algorithm, -7, "ES256 public key algorithm");
  phase("firefox-passkey-create:rp-verify");
  const server = externalServer();
  const registration = verifyRegistrationResponse({
    response: created.result.json,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rp,
    requireUserVerification: true,
  });
  assert.equal(
    created.result.json.clientExtensionResults?.credProps?.rk,
    true,
    "Resident-key credProps extension",
  );
  let serverCredential = null;
  if (server) {
    const checked = await server.verifyRegistrationResponse({
      response: created.result.json,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: rp,
      requireUserVerification: true,
    });
    assert.equal(checked.verified, true, "Independent WebAuthn registration rejected");
    serverCredential = checked.registrationInfo?.credential;
  }
  const leaked = await pageEval(pageLeakInPage, canaries);
  assert.equal(
    leaked.length,
    0,
    "Vault factor text found in the controlled page DOM",
  );
  assert(
    !canaries.some((value) => JSON.stringify(created.result.json).includes(value)),
    "Vault factor text found in the passkey credential",
  );
  // Native approval raised the host window. Raise Firefox before starting the
  // next ceremony so physical inline clicks target the browser, not the host.
  await dismissPopup();
  phase("firefox-passkey-get:page-request");
  const getChallenge = Buffer.from(
    "synthetic-firefox-get-challenge-02",
  ).toString("base64url");
  await pageEval(startGetInPage, {
    id: created.result.json.id,
    rp,
    challenge: getChallenge,
  });
  phase("firefox-passkey-get:inline");
  await clickInline("使用 Locklark 登录");
  const loginLabel = nativeLabel("get");
  assert.equal(
    loginLabel,
    "登录：" + rp + " · " + PASSKEY_CONTRACT.userName + " · " + PASSKEY_CONTRACT.userName,
    "Native login label must equal the allowlisted passkey label",
  );
  phase("firefox-passkey-get:native-factors");
  input([...verifyFactors, { click_label: loginLabel }]);
  phase("firefox-passkey-get:result");
  await eventually(
    async () => {
      const state = await pageEval(readResultInPage);
      return !!(state.result || state.error);
    },
    "Firefox passkey assertion did not complete",
    30000,
  );
  const signed = await pageEval(readResultInPage);
  assert(
    !signed.error,
    "PasskeyFailure:assertion-rejected:" + safeName(signed.error),
  );
  assert(
    signed.result?.instance && signed.result.response,
    "PublicKeyCredential/AuthenticatorAssertionResponse contract",
  );
  phase("firefox-passkey-get:rp-verify");
  const assertion = verifyAuthenticationResponse({
    response: signed.result.json,
    expectedChallenge: getChallenge,
    expectedOrigin: origin,
    expectedRPID: rp,
    publicKey: registration.publicKey,
    requireUserVerification: true,
  });
  if (assertion.userHandle)
    assert.deepEqual(
      assertion.userHandle,
      Buffer.from([1, 2, 3]),
      "Assertion userHandle must equal the requested user ID",
    );
  if (server) {
    const checked = await server.verifyAuthenticationResponse({
      response: signed.result.json,
      expectedChallenge: getChallenge,
      expectedOrigin: origin,
      expectedRPID: rp,
      credential: serverCredential,
      requireUserVerification: true,
    });
    assert.equal(checked.verified, true, "Independent WebAuthn authentication rejected");
  }
  await dismissPopup();
  phase("firefox-passkey-cancel:page-request");
  await pageEval(startCancelInPage);
  await eventually(
    async () => (await pageEval(readCancelInPage)) !== null,
    "AbortSignal was not honored by the passkey interception",
    15000,
  );
  assert.equal(
    await pageEval(readCancelInPage),
    "AbortError",
    "Aborted passkey request must reject with AbortError",
  );
  await eventually(
    () => inlineAbsent("使用 Locklark 登录"),
    "Closed-shadow passkey panel survived the aborted request",
    15000,
  );
  phase("firefox-passkey-cancel:native-cleared");
  await eventually(
    () => {
      const controls = input([], true, { inspect: true }).controls || {};
      return [nativeLabel("create"), nativeLabel("get")].every(
        (label) => !(controls[label]?.showing && controls[label]?.enabled),
      );
    },
    "Native passkey approval survived the aborted request",
    20000,
  );
  await dismissPopup();
  phase("firefox-passkey-browser-fallback:page-request");
  const fallbackChallenge = Buffer.from(
    "synthetic-firefox-fallback-challenge-03",
  ).toString("base64url");
  await pageEval(startFallbackInPage, { rp, challenge: fallbackChallenge });
  phase("firefox-passkey-browser-fallback:inline");
  await clickInline("使用其他验证器");
  await eventually(
    async () => (await pageEval(readFallbackInPage)).state !== undefined,
    "Browser fallback page state missing",
    15000,
  );
  await pause(1500);
  let fallback = await pageEval(readFallbackInPage);
  assert.notEqual(
    fallback.state,
    "resolved",
    "Browser fallback resolved with a Locklark credential",
  );
  assert.equal(fallback.result, null, "Browser fallback leaked a Locklark credential");
  assert.equal(
    await inlineAbsent("使用 Locklark 登录"),
    true,
    "Locklark panel survived the browser fallback",
  );
  if (fallback.state === "pending") {
    await pageEval(abortFallbackInPage);
    await eventually(
      async () => (await pageEval(readFallbackInPage)).state !== "pending",
      "Browser-owned fallback request ignored AbortSignal",
      25000,
    );
    fallback = await pageEval(readFallbackInPage);
  }
  phase("firefox-passkey-browser-fallback:outcome");
  assert(
    fallback.state.startsWith("rejected:"),
    "Unexpected browser fallback outcome: " + fallback.state,
  );
  if (process.env.LOCKLARK_TEST_PASSKEY_MANAGEMENT === "1") {
    await acceptPasskeyManagement({
      origin, fixture, first: created.result.json,
      openPopup: driver.openPopup, observe: driver.observe, reconnect,
      pageEval, inlineClick: clickInline, focusPage: () => input([], false),
      dismissPopup, eventually, input, phase,
    });
  }
  phase("firefox-passkey-complete");
  return {
    rp,
    registrationVerified: true,
    assertionVerified: true,
    independentWebAuthnServer: !!server,
    cancellationAbortError: true,
    browserFallbackHandedToFirefox: true,
    browserFallbackOutcome: fallback.state,
  };
}
// Verifier self-check: builds a synthetic none-attestation registration and an
// ES256 assertion, then requires the independent relying-party checks to accept
// them and to reject mismatched challenge, origin, RP ID, key and signature.
function cbHead(major, size) {
  if (size < 24) return Buffer.from([(major << 5) | size]);
  if (size < 256) return Buffer.from([(major << 5) | 24, size]);
  return Buffer.from([(major << 5) | 25, size >> 8, size & 255]);
}
const cbInt = (value) => (value >= 0 ? cbHead(0, value) : cbHead(1, -1 - value));
const cbBytes = (bytes) => Buffer.concat([cbHead(2, bytes.length), bytes]);
const cbText = (text) =>
  Buffer.concat([cbHead(3, Buffer.byteLength(text)), Buffer.from(text, "utf8")]);
const cbMap = (entries) =>
  Buffer.concat([cbHead(5, entries.length), ...entries.flat()]);

if (
  process.argv[1]?.endsWith("browser_firefox_passkey_acceptance.mjs") &&
  process.argv.includes("--self-check")
) {
  const { generateKeyPairSync, sign, randomBytes } = await import("node:crypto");
  const rp = PASSKEY_CONTRACT.rpID;
  const origin = "https://" + rp + ":8443";
  const challenge = Buffer.from("self-check-create").toString("base64url");
  const getChallenge = Buffer.from("self-check-get").toString("base64url");
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const spki = publicKey.export({ format: "der", type: "spki" });
  const point = spki.subarray(spki.length - 64);
  const credentialId = randomBytes(32);
  const cose = cbMap([
    [cbInt(1), cbInt(2)],
    [cbInt(3), cbInt(-7)],
    [cbInt(-1), cbInt(1)],
    [cbInt(-2), cbBytes(point.subarray(0, 32))],
    [cbInt(-3), cbBytes(point.subarray(32))],
  ]);
  const registrationAuth = Buffer.concat([
    sha256(rp),
    Buffer.from([0x45]),
    Buffer.from([0, 0, 0, 0]),
    Buffer.alloc(16),
    Buffer.from([credentialId.length >> 8, credentialId.length & 255]),
    credentialId,
    cose,
  ]);
  const attestation = cbMap([
    [cbText("fmt"), cbText("none")],
    [cbText("attStmt"), cbMap([])],
    [cbText("authData"), cbBytes(registrationAuth)],
  ]);
  const createClient = Buffer.from(
    JSON.stringify({ type: "webauthn.create", challenge, origin }),
  );
  const registration = {
    id: credentialId.toString("base64url"),
    rawId: credentialId.toString("base64url"),
    type: "public-key",
    response: {
      clientDataJSON: createClient.toString("base64url"),
      attestationObject: attestation.toString("base64url"),
      authenticatorData: registrationAuth.toString("base64url"),
      publicKey: spki.toString("base64url"),
      publicKeyAlgorithm: -7,
    },
    clientExtensionResults: { credProps: { rk: true } },
  };
  const accepted = verifyRegistrationResponse({
    response: registration,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rp,
    requireUserVerification: true,
  });
  assert.equal(accepted.verified, true, "Registration self-check");
  const reject = (operation, description) => {
    let threw = false;
    try {
      operation();
    } catch {
      threw = true;
    }
    assert(threw, "Verifier accepted " + description);
  };
  reject(
    () =>
      verifyRegistrationResponse({
        response: registration,
        expectedChallenge: getChallenge,
        expectedOrigin: origin,
        expectedRPID: rp,
      }),
    "a mismatched registration challenge",
  );
  reject(
    () =>
      verifyRegistrationResponse({
        response: registration,
        expectedChallenge: challenge,
        expectedOrigin: "https://evil.locklark.test",
        expectedRPID: rp,
      }),
    "a mismatched registration origin",
  );
  reject(
    () =>
      verifyRegistrationResponse({
        response: registration,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: "example.com",
      }),
    "a mismatched RP ID",
  );
  reject(
    () =>
      verifyRegistrationResponse({
        response: {
          ...registration,
          response: {
            ...registration.response,
            publicKey: Buffer.alloc(spki.length).toString("base64url"),
          },
        },
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rp,
      }),
    "a forged host public key",
  );
  const assertionAuth = Buffer.concat([
    sha256(rp),
    Buffer.from([0x05]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const getClient = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge: getChallenge, origin }),
  );
  const signature = sign(
    "sha256",
    Buffer.concat([assertionAuth, sha256(getClient)]),
    privateKey,
  );
  const assertion = {
    id: registration.id,
    rawId: registration.rawId,
    type: "public-key",
    response: {
      clientDataJSON: getClient.toString("base64url"),
      authenticatorData: assertionAuth.toString("base64url"),
      signature: signature.toString("base64url"),
      userHandle: Buffer.from([1, 2, 3]).toString("base64url"),
    },
  };
  const acceptedAssertion = verifyAuthenticationResponse({
    response: assertion,
    expectedChallenge: getChallenge,
    expectedOrigin: origin,
    expectedRPID: rp,
    publicKey: accepted.publicKey,
  });
  assert.equal(acceptedAssertion.verified, true, "Assertion self-check");
  assert.deepEqual(acceptedAssertion.userHandle, Buffer.from([1, 2, 3]));
  reject(
    () =>
      verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rp,
        publicKey: accepted.publicKey,
      }),
    "a mismatched assertion challenge",
  );
  reject(
    () =>
      verifyAuthenticationResponse({
        response: {
          ...assertion,
          response: {
            ...assertion.response,
            signature: Buffer.alloc(70, 7).toString("base64url"),
          },
        },
        expectedChallenge: getChallenge,
        expectedOrigin: origin,
        expectedRPID: rp,
        publicKey: accepted.publicKey,
      }),
    "a forged assertion signature",
  );
  console.log(
    "SELF-CHECK: independent relying-party registration and assertion verification passed",
  );
}

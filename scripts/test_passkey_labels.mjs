import assert from "node:assert/strict";
import {
  passkeyChoiceLabel, passkeyCredentialHint, passkeyPopupHint,
} from "./browser_passkey_management_acceptance.mjs";

const id = "AbCdEfGhIjKl";
const rp = "login.locklark.test";
const title = rp + " · passkey-test";
assert.equal(passkeyCredentialHint(id), "AbCdEfGh…");
assert.equal(passkeyPopupHint(id), "AbCdEf…GhIjKl");
assert.equal(
  passkeyChoiceLabel({ rp, title, username: "passkey-test", credentialId: id }),
  "登录：login.locklark.test · login.locklark.test · passkey-test · passkey-test · 凭据 AbCdEfGh…",
);
assert.equal(
  passkeyChoiceLabel({ create: true, rp, title, username: "passkey-test", credentialId: id, existing: 1 }),
  "保存到：login.locklark.test · login.locklark.test · passkey-test · passkey-test（已有 1 个 Passkey） · 升级加密格式，旧客户端将拒绝该金库",
);
console.log("PASS: exact GET and CREATE Passkey labels");

# Multiple Passkey acceptance scripts

Status: primary-agent real headed Edge and Firefox runs passed the complete multi-credential and conditional-picker journeys. Edge verified source `0d0a7a6`; Firefox verified source `ab4416a`. These are functional browser/native-signature results, separate from static checks. Rebased code preserves the same feature changes on merged HIBP main.

The shared `scripts/browser_passkey_management_acceptance.mjs` journey now covers:

- an initial `[1,2,3]` / `passkey-test` registration and a separate `[4,5,6]` / `passkey-other` account;
- a second `[1,2,3]` / `passkey-test` registration that selects the existing login by the exact CREATE label, including `（已有 1 个 Passkey） · 升级加密格式，旧客户端将拒绝该金库`;
- one unchanged first parent ID, an independent ES256 registration and exact native GET label;
- the real popup detail selector: placeholder first, no automatic first credential, physical label click plus keyboard selection of the second credential by public credential ID, then public RP/account/hint checks;
- signing with the second credential through `navigator.credentials.get`, deletion of only that sibling with the two-step confirmation, and fresh first/other-account assertions;
- an optional conditional account-picker case for two siblings under one parent, selecting the second full public selector rather than the first record.

Native GET labels mirror `internal/desktop/browser.go`: prefix + RP + stored title + username + ` · 凭据 ` + first eight Base64URL characters + `…`. CREATE labels omit the credential hint and append the existing-count/warning suffix. Selectors are exact; no first-button fallback is used.


The actual journeys found and fixed two product defects: native review choices outside the default window, and whole-item editing that restored only legacy `Passkey` while dropping versioned `Passkeys`. The final runs cover native full-factor approval, the exact second credential signature, conditional selection, removal followed by a rejected request for that deleted credential, survival of sibling/other accounts, password/notes editing without key loss, cancellation and reconnect persistence. Independent edit-preservation race test passed (11.133 seconds); native viewport tests passed (1.309 seconds). No private key or factor entered browser messages or public evidence.

Windows/macOS interactive acceptance, system Hello/Touch ID, signed Safari installation and full positive iOS acceptance remain separate requirements; GitHub iOS green from capability denial is not positive platform acceptance (issue #69).

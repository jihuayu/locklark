# Browser experience parity: Chrome / Edge first

This development change adds inline password selection, opt-in quick native
pairing, configurable automatic submission, and software Passkey creation and
assertion. It is **not complete 1Password parity**. Chrome/Edge share the Chromium
build; an actual Edge run is still required before claiming Edge validation. Remaining work is tracked in [issue #39](https://github.com/jihuayu/locklark/issues/39).

The behavior references are 1Password's public [save and fill](https://support.1password.com/save-fill-passwords/),
[Passkey](https://support.1password.com/save-use-passkeys/), and
[browser getting-started](https://support.1password.com/getting-started-browser/)
guides. No proprietary source, branding, or assets are copied.

## Coverage

| Capability | Current implementation | Remaining work |
| --- | --- | --- |
| Inline account selection | Closed-shadow UI, keyboard navigation, sender/document binding | More website fixtures; custom and shadow-DOM fields |
| Unlock and pairing | Native unlock from popup/inline offer; bounded quick or per-operation mode | Share desktop unlock state; platform biometrics |
| Password filling | Semantic visible username/password fields; individual two-step screens; framework input/change events | Continuous multi-step journeys, iframe policies, additional fields |
| Automatic login | Explicit account selection; global and per-login opt-out; guarded POST submission | Broader compatibility, Open & Fill, successful-login detection |
| Save/update | Explicit inline/popup action; capture/approval/commit handshake | Post-submit suggestions; signup/change-password forms and generated password recovery |
| Password generation | Existing native generator | Inline configurable generator and generated-password history |
| TOTP | Popup and inline standard single-field filling; quick mode or native approval | Split OTP fields and optional linked login flow |
| Passkey registration | ES256, discoverable credential, create login or attach to existing; exclude list | Additional algorithms/extensions; separate credential removal |
| Passkey sign-in | RP/allow-list matching, native account selection, standard credential response | Immediate conditional account list; related origins; iframe support |
| User verification | Fresh native master-password + Secret Key verification; truthful UV flag | Windows Hello / Touch ID integration for this flow |
| Passkey persistence | Protected encrypted KDBX field, atomic creation/audit, backup/restore | Cross-device sync validation, import/export interoperability beyond protected KDBX |
| Browser fallback | Original `navigator.credentials` path; separate save/use offer settings | Full coexistence tests with other password managers; WebAuthn signal APIs |
| Other browser features | Existing native search/notes/health tools | Extension vault editing/search, cards/identities, item sharing, Watchtower UI, privacy email/service integrations |
| Release | Development build and existing native registration tools | Actual Edge/Firefox/macOS/Windows runs, store packages/signing/update distribution |

## Trust boundaries

The MAIN-world wrapper only serializes WebAuthn buffers and reconstructs standard
credential responses. The isolated script handles the visible choice and forwards
a bounded request. The worker obtains origin, top frame, active tab/window and
document identity from browser APIs. The native host independently validates RP
ID boundaries using the public suffix list, including private suffixes.

Native approval supplies user presence. Only fresh native factor verification
supplies UV; pairing, unlocking earlier, and Secret Service retrieval do not.
Older binaries that do not understand the optional Passkey field/audit actions will refuse a vault after it contains Passkeys; use a current binary and keep a pre-upgrade backup. Private keys never cross native messaging. Assertion signatures/client data do
cross it, only for the approved request. Creation persists its key and dedicated
audit event atomically. Lock/cancel/deadline revokes a registered mutation gate;
output authority is rechecked after waiting for the writer slot. A transaction or
injection already granted may have completed; cancellation cannot recall it.

Extension storage contains preferences and per-login override IDs only. Broad
HTTPS host permission is now necessary for document-start integration and inline
UI. Passwords still travel directly from the worker's bounded response to an
isolated script targeting the original document. Page messages cannot request
password fields or choose their signing origin. Top-level-only support and
Permissions Policy checks intentionally preserve the current boundary.

## Verification

- Node worker/UI policy tests: sender forgery, document changes, cancellation,
  late responses, settings and retained unknown password-fill outcomes.
- Go crypto tests independently verify ES256 signatures, RP/challenge data,
  flags, allow/exclude behavior and invalid/public-suffix RPs.
- Native-host tests exercise actual vault persistence and native-only approval;
  personal/vault tests cover protected KDBX storage, stale revisions, cancellation,
  fresh-factor refusal, overwrite refusal, and backup/restore/sign-in.
- Controlled Chromium and Firefox DOM checks cover semantic and individual multi-step fields,
  input/change events, automatic submission and post-event action mutation.
- Real Linux Chromium/native MyGo acceptance uses AT-SPI and XTest for unlock,
  quick pairing, inline account selection, automatic submission, Passkey
  creation, verified assertion and AbortSignal. The relying-party verifier uses
  the returned public key to check the signature independently.

The native UI script accepts `LOCKLARK_TEST_BROWSER_PARITY=1` to run this new
journey independently of the longer legacy save/OTP scenarios. It still uses the
actual product binary and native UI; there is no test approval flag. Optional
`LOCKLARK_TEST_WEBAUTHN_SERVER` points to an installed `@simplewebauthn/server`
package for independent CBOR/COSE and WebAuthn registration/assertion validation.
Test dependencies and synthetic vaults belong in temporary private directories.

No actual Edge run, new Firefox Passkey run, macOS/Windows biometric run, public
website compatibility survey, store release or external security audit is claimed.

## Recorded checks (2026-11-06)

- `go test ./...`: passed.
- `go vet ./...`: passed.
- Focused `go test -race` for Passkey, quick pairing and queued-output cancellation: passed.
- `node --test browser-extension/test/*.test.js`: 57 tests passed.
- Chromium 143 (Playwright 1.57) real DOM and native Passkey/quick-login journey: passed.
- `@simplewebauthn/server@14.0.3` independently accepted registration and authentication in that real native journey.
- The longer legacy native UI suite encountered intermittent action-popup focus/readiness failures on Chromium 143. Re-running with the repository-pinned Playwright 1.64.1 / Chromium 156 passed the complete fill/save/update/OTP and new Passkey journey, including the independent WebAuthn verifier.

The new native journey was exercised with real factor entry and native approvals,
including UV-required creation and sign-in. Synthetic private factors were not
printed in test output or copied into this repository.

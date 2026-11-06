# Native iOS personal vault

This SwiftUI app calls the real `mobile/core` Go package through a gomobile
XCFramework and a narrow Objective-C adapter. It has no WebView, network upload
method, sample repository, system autofill extension or Passkey implementation.

The current flow creates a personal encrypted vault after explicit Secret Key
backup acknowledgement, then requires both full factors to unlock. It supports
title-only search, login creation, generated passwords, exact-revision field
edits, regeneration and explicit bounded username/password/notes/TOTP display.
It does not automatically copy secrets or fetch the next OTP window.

## Build and test on macOS

Use Xcode with the iOS 17+ SDK and simulator runtime, Go 1.27.3, Python 3, curl
and unzip. From the repository root:

```sh
GO_BIN=go mobile/ios/scripts/ci.sh
```

The script installs gomobile/gobind at the exact version pinned in root go.mod,
binds both iOS device and simulator targets into `Build/Mobilecore.xcframework`,
verifies the SHA-256 of XcodeGen 2.46.0, generates the project, runs pure Swift
tests, creates a fresh simulator and runs actual SDK adapter/core/UI tests.
No prebuilt or fake framework is accepted. For local signed-device work, run
the two build/generate scripts and open `Locklark.xcodeproj`, then choose your
own development team. The generated project and build products are ignored.

Runtime output, XCTest result bundles and screenshots under `Build/` are
private synthetic-fixture evidence and may contain intentionally shown values.
Do not upload those files or print the runtime log. The CI entry prints fixed
PASS/FAIL labels and allowlisted source locations/fixed failure reasons. The
independent evidence verifier checks the complete runtime and exported result
objects, including failed runs, against the private runner canary manifest.
UI fixtures enter factors through the runner pasteboard and
the system Paste action, clear it immediately, and use fixed boolean assertion
messages instead of value diffs. There are no production test hooks or secret
launch arguments.

The independent Foundation logic can also run on Linux with Swift 6:

```sh
swift test --package-path mobile/ios/SecurityLogic
```

## Platform security and current verification limits

The database directory and every existing database/sidecar are excluded from
backup and receive complete file protection. A signed app also declares
`NSFileProtectionComplete` as its default data protection. Actual Go-created
file protection is checked before post-create strengthening; failed protection
locks the app and disables further use. Reopening checks the actual attributes.
No account factor, local device key or capsule is put in a backup file.
Protection writes use Apple's documented NSURL `fileProtectionKey` interface;
the fresh authoritative URL getter must equal `URLFileProtection.complete`.
Missing or weaker values are rejected, including on a simulator. Legacy
FileManager attribute representations are diagnostic evidence, not substitutes
for a positive authoritative protection result.

Quick unlock defaults off. An explicit enable action after complete two-factor
unlock stores only the core's audited 24-hour, original-path/slot-bound sealed
identity capsule. Keychain uses `WhenPasscodeSetThisDeviceOnly`, user presence,
non-synchronizing entries and no plaintext or weaker-accessibility fallback.
This does not claim that the software age/Ed25519 keys are Secure Enclave keys.

Every inactive/background transition immediately covers the UI, clears text
and drafts, invalidates ordinary UI work and requests the core lock. A Go-issued
expected-epoch operation view is captured on the UI actor before queueing;
worker cancellation tickets reject old queued work and clear captured buffers
even when the operation never starts. New operations wait for lifecycle lock
cleanup, so a late cleanup cannot revoke a newly captured unlock. Blocking
cleanup and SecretValue.Clear run off the UI thread, including handle dealloc.
Late results must match the operation owner, UI generation, exact selected
ID/revision/field and unlocked core; disclosure also obeys both wall and
monotonic budgets. Foregrounding never retries authentication automatically.

System unlock first checks capsule presence without reading its data or opening
a prompt. An explicit OS preauthentication runs while the vault remains locked
and covered. Only this separately owned, secret-free attempt can wait through
its prompt's inactivity; actual backgrounding always cancels it. After success,
the same attempt must be active, within its original ten-second monotonic
authorization budget and past all lock cleanup before any core unlock starts.
Keychain receives that single-use context with interaction disallowed, so its
data load cannot start a second prompt. The covered phase retains an explicit
cancel action through the core worker. No ordinary unlocked session survives
inactivity, and complete factors remain available when system authentication
is unavailable, cancelled or expired.

Linux verification covers the pure state/deadline/control-character logic and
source syntax only. Apple SDK compilation and actual simulator tests require
macOS CI; passcode/Face ID policy, system-prompt scene transitions, device-only
non-migration, reboot, backup/restore and signed-device protection still require
independent hardware checks. Existing core audit actions retain their legacy
`desktop.*` namespace and do not establish a distinct signed mobile provenance.

# Native core validation

The core uses the actual encrypted personal vault and signed audit journal on
disk. It has no synthetic repository, network backend, or team upload method.

## Android publication correction after v3

Actual Android acceptance refused vault creation. Android's AOSP policy
`private/app_neverallows.te` explicitly forbids hard links for all untrusted
applications, including their own files. The old personal publisher used
`os.Link`; a real Android shell-UID filesystem probe also returned EACCES (13)
for that operation. The official policy is available at
<https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/app_neverallows.te>.

The v4 correction changes only Android publication to kernel-enforced
`renameat2(RENAME_NOREPLACE)`. It preserves the complete-file fsync before
publication and directory fsync afterwards. Existing destinations cannot be
overwritten, concurrent creation has one complete winner, and directory-sync
failure leaves the complete published file for inspection. An unsupported
kernel/filesystem fails closed; there is no hard-link, replacing-rename or
placeholder fallback. iOS retains its original publisher, and Linux desktop
continues using its original publisher.

The four publication regressions passed on the host (0.019s normal, 1.039s race).
The exact same Go tests were crosscompiled for Android and executed on the
owned API 35 emulator, where all four passed: existing target preservation,
one complete concurrent winner, complete-file retention on directory-sync
failure, and unsupported-kernel refusal. That execution was shell UID 2000,
not the installed app's untrusted-app UID/SELinux domain. It proves the real
Android kernel/Go atomic helper, while installed-app JNI and UI acceptance
remain separate platform checks.

A private app_process JNI harness reached its filesystem probe but exited
before reporting the Go key/create phases. That harness is not recorded as a
JNI or application success. The original failing CI application result and all
private diagnostic artifacts are retained.

The v4 AAR warm bind passed with 89 exact transitive inputs (84 platform files
per Android ABI), before/after input equality and zero current mismatches.
The immutable local artifact under `/tmp/locklark-tools/mobile/core-final-v4`
has SHA-256 `f306122940008c1e81bc45f91112fff32771d036d5120328fd08cf7196a3cd8f`;
its source manifest has SHA-256
`45556f2cfce45630a6e956c115a49e048424187c6e28af1d5ba01c4eb93b99a7`.
Installed-app JNI/UI proof must use this corrected artifact or a fresh binding
from the same source, and is not implied by the shell-UID helper tests.

## v3 security result retained by v4

CaptureOperation returns an immutable epoch-bound Vault view over shared state.
Native UI captures that view before queueing work; the controller remains the
lifecycle owner. Deterministic tests first reproduced stale Create, Unlock and
Edit crossing the native preflight-to-Go-call gap, then passed with bound-view
enforcement. Tests also cover stale-view recapture, bound IsUnlocked, shared
RequestLock, inert default binding constructors, and a fresh capture surviving
cleanup when no session overtook Lock. The latter cleanup test also failed
before the conditional re-invalidation fix.

The entire current core normal suite passed in 11.034s and its entire race
suite passed in 109.560s (`GOMAXPROCS=2`, `-p 1`, `-count=1`, no test-name filter).
The parent and independent reviewer reran the focused capture/queue/OTP tests
with corrected regexes selecting the full names. Repo-wide vet passed again
after v3, and module verification again reported `all modules verified`.

The final v3 warm bind passed with matching before/after hashes for 88 exact
transitive source/build inputs and the pinned binding-tool binaries. Current
source re-verification found zero mismatches. Immutable local artifacts are
under `/tmp/locklark-tools/mobile/core-final-v3`:

- AAR SHA-256: `edc91ce26a07a83d381be8e2428a404bec1ce6224e8dca177324bae6ef859593`
- Manifest SHA-256: `0c2eaffab9a9e12d1570613feec3acbe53f50fabd3a1322fc6c2aaa59976ca76`
- Before-bind manifest SHA-256: `4f2ecde39c16a91c2431aae1eb264a4ebd2f8e81d9d0619b1c409601b26c36d0`

The v1/v2 artifacts and all failed/green logs remain available as historical
evidence. A final v3 repo-wide test run is delegated to final-head CI; the local
35-package baseline run below is explicitly not claimed as a v3 tree run.

## Meaningful behavioral red / green evidence

The initial missing-API compiler failure is an API red check, not behavioral
evidence. These later tests ran against implemented behavior and failed before
their corresponding fixes:

- `TestMobileLockBeforeFinalGrantRefusesCopiedBytes` failed with
  `lock won before final grant but copied bytes escaped`. A controlled barrier
  advanced RequestLock after the earlier split validation. The final short
  delivery grant now arbitrates under the same wrapper mutex as RequestLock.
- `TestMobileFieldHandleDefersDisclosureAndRejectsOtherSessionEdit` failed with
  `metadata handle prefetched and audited a secret before explicit Take`.
  RevealField now creates a metadata-only handle. Take performs its one fresh
  exact-revision authenticated read and disclosure intent. A second Session
  editing after RevealField makes Take return a conflict with no value.
- `TestMobileClearCancelsWithoutWaitingForTakeWorker` failed with
  `Clear blocked on a disclosure worker`. Clear now atomically cancels, detaches
  the handle, and schedules once-only cleanup without waiting for disk work.
- The generic native edit test initially failed on the next authenticated list
  after an invalid password was refused. The signed event verifier had accepted
  `native-refused` only for notes and generation. It now accepts that result for
  the same six explicit native field actions allowed by the mutation gate.
- A later concurrency review added two OTP grant regressions that failed:
  rollback within the original period escaped the wrapper, and the exposed
  native lower bound was the period start rather than the latest checked sample.
  The final grant now rechecks the copied OTPBounds wall/monotonic observation
  and exposes its last verified wall sample as FromUnixMilli.
- Three queued lifecycle regressions failed: an old queued unlock adopted a new
  epoch, an overtaking unlock remained installed when Lock returned, and an old
  queued mutation used a freshly unlocked session. Operations now capture their
  caller epoch before waiting for the worker mutex and recheck it afterwards;
  Lock invalidates once more while it owns that mutex.

Those five new review regressions passed together in 2.944s. The complete v2 core
normal test suite passed in 10.212s and the complete v2 core race suite passed in
88.963s (`GOMAXPROCS=2`, `-p 1`, `-count=1`). An independent reviewer repeated the
five review regressions twice and cleared the updated concurrency design.
Successful empty username/notes disclosures are covered;
gomobile intentionally coalesces empty byte slices to native nil/null, so native
adapters normalize that successful empty result without swallowing errors.

The tests additionally cover both wrong unlock factors, encrypted offline
persistence, stable IDs/revisions, stale mutations, Unicode title search,
generated password receipts, explicit one-use disclosure, OTP validity bounds
without seed access, eight-handle capacity, late authenticated OS callbacks,
lock before a disk-blocked mutation commit, and grant-before-lock delivery
semantics requiring the native UI to reject a stale generation.

## Completed checks

```sh
GOTOOLCHAIN=go1.27.3 go test ./mobile/core ./internal/personal \
  -run 'TestMobile|TestNativeFieldEditUses' -count=1
GOTOOLCHAIN=go1.27.3 go test -race ./mobile/core ./internal/personal \
  -run 'TestMobile|TestNativeFieldEditUses' -count=1
mobile/scripts/bind-android.sh
```

Targeted normal checks passed (core 21.974s, native edit 5.196s). Targeted race
checks passed (core 69.996s, native edit 16.383s). The Android build script ran
with real SDK 36/build-tools 36, NDK 27.2.12479018 and JDK 21.0.13+9. It produced
the real API 30 AAR for arm64-v8a and x86_64. The local artifact and complete
source hash manifest are ignored build outputs under `mobile/core/build`.
The source manifest records its AAR SHA-256; APK acceptance must use that exact
artifact or rebuild through the same pinned script.
The historical v1 warm bind captured 88 transitive source/build inputs (83 platform
source files for each Android architecture), including go:embed payloads and
binding script hashes. The tool verifies that source, module and installed
binding-tool hashes match before and after binding; it excludes unrelated team
sync code. Historical v1 AAR SHA-256 (superseded by the v2 review fixes):
`b1f336c36c25a839f40354327e60213ce48c6265c2a5a680e04ca0b5685dfefe`.

The pinned `golang.org/x/mobile` version is
`v0.0.0-20260908204917-8b95e45f8d3e`, checksum
`h1:zYnHsDmxfxKH/x9DjYNAdoIdMsP8enB1Ncb10b3pdHk=`. Both binding tools use this
version, which preserves the existing x/image v0.46.0 desktop dependency.
Both personal Android arm64 and iOS arm64 CGO-disabled compile probes passed.
Objective-C header generation is a binding API check; a real XCFramework and
Apple SDK app build require the macOS CI job and are not claimed by this Linux
core validation.

## Incomplete broad race run

An earlier `go test -race ./mobile/core ./internal/personal` passed the then
current core tests in 38.769s, but the complete personal suite did not pass.
`TestBrowserOTPConcurrentGrantAndOutputAreSingleUse` expired its existing clock
budget after 19.88s. The suite then hit its default ten-minute timeout at
600.086s while executing PBKDF2 in an unrelated browser fixture. No data-race
report appeared. This run occurred with concurrent SDK/compiler work on the
shared four-vCPU environment. It is retained as a failed/incomplete run; neither
the production TTL nor existing browser tests were loosened for this increment.

The complete personal normal regression passed separately with a 20-minute
timeout (`go test ./internal/personal -timeout=20m -count=1`, 369.975s).
The authorized repo-wide normal run also passed all 35 package statuses with
`GOMAXPROCS=2 go test -p 1 -count=1 ./... -timeout=20m` and explicit Bun/PyKeePass
paths (personal 275.009s, then-current core 7.087s). That run started before the
later v2 review fixes; its core binary did not include the deliberately failing
new regressions. It is baseline repo-wide evidence, not a final v2 tree run.
After the v2 fixes, repo-wide `go vet -p 1 ./...` passed and `go mod verify`
reported `all modules verified`. Full logs, genuine red logs, and the explicit
baseline-versus-v2 coverage note are under `/tmp/locklark-validation` in the
validation workspace; those private runtime artifacts are not repository files.
Native system authentication, non-migrating Keychain/Keystore keys,
backup exclusion and real-device install remain platform acceptance work.

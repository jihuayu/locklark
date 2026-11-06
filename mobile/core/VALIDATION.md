# Native core validation

The core uses the actual encrypted personal vault and signed audit journal on
disk. It has no synthetic repository, network backend, or team upload method.

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
The final warm bind captured 88 transitive source/build inputs (83 platform
source files for each Android architecture), including go:embed payloads and
binding script hashes. The tool verifies that source, module and installed
binding-tool hashes match before and after binding; it excludes unrelated team
sync code. Final AAR SHA-256:
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
Native system authentication, non-migrating Keychain/Keystore keys,
backup exclusion and real-device install remain platform acceptance work.

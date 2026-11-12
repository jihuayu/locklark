# Native Android client

This app links the real `mobile/core` Go binding. It has no JavaScript renderer,
network vault repository, embedded unlock factors, or fallback data source.
Android 11 / API 30 is the minimum supported OS for the first native client.

## Build

Use JDK 21, Android SDK platform 36, build-tools 36.0.0 and NDK
27.2.12479018. The Gradle wrapper pins 8.13 and its SHA-256; Android Gradle Plugin
8.13.2 and Kotlin 2.2.21 are pinned in the root build file. Build the real Go AAR
first using the core's binding script, including `android/arm64` for phones and
`android/amd64` for the x86_64 emulator. Its default location is
`mobile/core/build/mobilecore.aar`; `LOCKLARK_MOBILE_AAR` can select another
explicit artifact. Missing bindings fail the build.

```sh
JAVA_HOME=/path/to/jdk21 ANDROID_HOME=/path/to/android-sdk \
  mobile/android/scripts/build.sh
```

The default tasks run JVM policy tests and build the debug app and separate
instrumentation APK. On a disposable, running emulator, the normal gate selects
the three mandatory native UI/core/autofill tests and privately scans their logs:

```sh
ANDROID_HOME=/path/to/android-sdk ANDROID_SERIAL=emulator-5554 \
  LOCKLARK_ANDROID_TEST_RESET=1 mobile/android/scripts/test-emulator.sh
```

After the independent host UI gate has produced exactly one completed private
run, `scripts/test-device-credential.sh` performs a separate real device-PIN
flow. It requires `--authorize-device-pin-setup` on a verified emulator, takes
`--evidence-root` for that exact host run's parent directory, and removes only
the PIN it established. It selects `DeviceKeyProtectionTest` only after actual
opt-in/quick-unlock/cancellation, then checks nonexportability and per-operation
OS policy. It also checks that restoring encrypted vault/capsule files after
reinstall does not transfer the old OS key. A direct unfiltered
`:app:connectedDebugAndroidTest` requires that same prepared OS-auth fixture;
it is not a replacement for these ordered gates.
A compiled APK or software emulator does not establish hardware-backed Keystore,
real biometric sensor or real-device credential behavior.

## Native safety boundary

Full factors use native input widgets. The app blocks screenshots and view-state
persistence; it locks and cancels work on background, and invalidates late
callbacks after a change of target or UI generation. Revealed values are
single-use core deliveries; both original core time bounds and a monotonic UI
expiration budget apply. Native text widgets and Java strings can have transient
managed-memory copies; the client clears references and mutable buffers but does
not claim physical erasure of every runtime copy.

Optional device authentication protects only the core's audited 24-hour capsule.
An auth-per-operation AES-GCM key remains in Android Keystore. Ciphertext and its
per-install alias metadata live under `noBackupFilesDir`. Unsupported or cancelled
OS authentication fails closed. Cloud backup and device-to-device transfer rules
exclude all app data; no local key or capsule is a transferable recovery method.

## Autofill explicit-approval fill checkpoint

The registered `AutofillAuthService` inspects only the newest OS
`AssistStructure` and accepts only one explicitly hinted username/email field
followed by one password field. It refuses unhinted, ambiguous, OTP, card,
hidden, disabled or malformed input, and it never reads field values, saved
values or vault data. A matching request creates a process-local random
one-use record bound to the target package and exact `AutofillId`s for at most
60 seconds; restart, expiry and replay fail closed. The response that the OS
shows first is an authentication challenge with no Dataset and no value.

The OS launches the explicit, non-exported auth Activity through an app-private
one-shot `PendingIntent` that is mutable from API 31 (`FLAG_MUTABLE` exists only
there, so API 30 never receives it). The Activity claims that one-use record (a
configuration-change restart cannot claim it again), revalidates the
OS-attached structure, package, `AutofillId`s, client-state nonce and token,
opens a brand-new vault on the app's own `noBackupFilesDir/personal.ll`, and
unlocks it only with the entered master password and Secret Key. It then lists
active login metadata, and the user selects one visible title and presses a
separate Approve. Approve revalidates the exact row ID/revision, reads only that
row's username/password into one-use buffers, and, once the serialized worker
delivers them, builds a `FillResponse` containing exactly one `Dataset` whose
two values are mapped only to the consumed request's `AutofillId`s. `setResult`
then returns `RESULT_OK` with a non-null `AutofillManager.EXTRA_AUTHENTICATION_RESULT`
holding that response (never a Dataset). The BOUND handoff is retired with
exactly that token, client nonce, package and the two OS `AutofillId`s before
`RESULT_OK`; a refused/replayed/wrong-target handoff or a malformed or missing
binding argument returns no fill and retires the record. Every approval and
caller byte buffer is cleared before the result leaves the Activity, the fresh
vault is locked synchronously and its one close is queued, and the Activity
finishes. The
dataset presentation is static and non-secret; no credential is rendered,
logged, saved or placed in an unrelated extra. After the user selects the
returned Dataset, Android fills only those two bound fields.

API 33+ uses the isolated `Dataset.Builder.setField(Field)`/`Presentations`
menu path; API 30-32 use the supported legacy `setValue` overloads, so minSdk 30
is preserved and the API 33-only types are never loaded on older runtimes.
A challenge response that cannot be parceled is never assumed to be zero bytes
under the bounded reviewed-response cache: it is not cached or returned, and
the request fails closed. Cancel, back, backgrounding, failure and a
missing/unopenable database remain no-fill: they return `RESULT_CANCELED` with
a non-null empty extras Bundle (as Android 12+ requires) and a successful
result can never be overwritten afterwards. Known browser packages, web/HTML
forms and opaque targets fail closed beyond the package + exact-ID binding;
this checkpoint has no save support, credential provider or Passkey
functionality.

The instrumentation suite uses only a synthetic test-APK login target and a
test-only `personal.ll` fixture created through the real mobilecore JNI APIs
under the app's private target storage. It proves both flows against the real
OS: the positive flow enters fresh synthetic factors, selects the row, presses
Approve, observes Android offer and apply the returned Dataset, and asserts both
target fields equal the fixture; the cancel flow proves both fields stay empty.
All fixture factors and values are recorded in the private canary file and the
runtime gate scans its private logs, so accidental disclosure fails the run.
The narrow Autofill-only gate selects exactly the owned emulator and API 36,
clears only that emulator's app/test data before and after, and saves/restores
its prior `autofill_service`:

```sh
ANDROID_HOME=/path/to/android-sdk ANDROID_SERIAL=emulator-5572 \
  LOCKLARK_ANDROID_TEST_RESET=1 LOCKLARK_ANDROID_AUTOFILL_ONLY=1 \
  mobile/android/scripts/test-emulator.sh
```

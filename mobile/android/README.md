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
the two mandatory native UI/core tests and privately scans their logs:

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
System autofill, credential providers and Passkey functionality are separate
work and are not declared here.

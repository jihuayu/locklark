# Android per-operation authentication ordering

The device capsule key remains AES-256/GCM in AndroidKeyStore with user authentication required, timeout zero, and `AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL`. Each encryption/decryption uses its own `BiometricPrompt.CryptoObject`. Background/lock cancels it; this change adds no lifecycle exemption or authentication cache.

The operation order is: initialize the cipher, request real OS authentication, require the same authenticated cipher and current lifecycle, feed the unchanged path/slot-bound AAD, then `doFinal`. Recheck current lifecycle before returning bytes; cancellation wipes the returned buffer.

This order is required by the Android 15 implementation at immutable release tag `android-15.0.0_r1`:

- [`AndroidKeyStoreAuthenticatedAESCipherSpi.java`](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/keystore/java/android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi.java): `createAdditionalAuthenticationDataStreamer` uses chunk threshold zero; `AdditionalAuthenticationDataStream.update` calls `KeyStoreOperation.updateAad` immediately.
- [`AndroidKeyStoreCipherSpiBase.java`](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/keystore/java/android/security/keystore2/AndroidKeyStoreCipherSpiBase.java): `engineUpdateAAD` invokes that streamer and caches a Keystore failure for later cipher completion.
- [`BiometricPrompt.java`](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/core/java/android/hardware/biometrics/BiometricPrompt.java): the crypto object binds authentication to its Keystore operation; API 30+ permits device credentials with strong-biometric crypto policy.

The earlier app fed AAD before authentication on both storage paths. The thirteenth CI run proved secure lock-screen capability and successful owned PIN setup, then observed a generic enable refusal without an OS credential marker. It did not preserve enough detail to establish that AAD was the sole cause of that run's refusal. The ordering defect is fixed independently; the next real emulator OS prompt gate must establish the actual outcome.

Diagnostics contain only fixed stage, failure, allowlisted exception category and allowlisted OS error category. A process-local attempt counter and app PID bind them to the initiated action. The host harness records a floor before the UI tap, accepts only a subsequent begin/failure pair for the same live PID and newest attempt, and never prints arbitrary exception text, paths, key aliases, capsules, factors, or OS error strings. The Go boundary continues to normalize storage failures; the Kotlin callback retains only its own attempt's fixed classification for native reporting.

JVM ordering/cancellation tests and Android compilation cannot prove successful OS authentication or physical hardware protection. The native gate must perform real PIN enrollment, capsule encryption/decryption, cancellation, and fresh unauthenticated-key refusal. Its reported Keystore security level is evidence about the emulator, not a physical device claim.

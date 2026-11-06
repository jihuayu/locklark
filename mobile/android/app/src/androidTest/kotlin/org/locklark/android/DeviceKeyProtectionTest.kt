package org.locklark.android

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.system.Os
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import org.locklark.android.security.NativeFailures
import org.locklark.android.verification.AuthenticationFailureFacts
import org.locklark.android.verification.AuthenticationDenial
import org.locklark.android.verification.DeviceKeyPolicyOracle

/** Explicitly selected only after the host completes real OS credential auth. */
@RunWith(AndroidJUnit4::class)
class DeviceKeyProtectionTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private var stage = "start"
    private var assertion = "none"
    private val metadata = linkedMapOf<String,String>()

    private fun report(next: String, check: String = "none") {
        stage = next; assertion = check
        instrumentation.sendStatus(0, Bundle().apply {
            putString("locklark_key_stage", stage)
            putString("locklark_key_assertion", assertion)
            metadata.forEach { (name, value) -> putString(name, value) }
        })
    }
    private fun policy(next: String, check: String, valid: Boolean) {
        report(next, check)
        assertTrue("Device key policy assertion failed", valid)
    }

    private fun authenticationFacts(error: Throwable): AuthenticationFailureFacts {
        if (error.javaClass == UserNotAuthenticatedException::class.java) return AuthenticationFailureFacts.UserNotAuthenticated
        if (Build.VERSION.SDK_INT >= 33 && error is android.security.KeyStoreException && error.javaClass == android.security.KeyStoreException::class.java) {
            return AuthenticationFailureFacts.KeyStore(error.numericErrorCode, error.requiresUserAuthentication(), error.isSystemError)
        }
        // Older SDKs expose the specific UserNotAuthenticatedException path;
        // unknown wrapped causes are refused without hidden API reflection.
        return AuthenticationFailureFacts.Other
    }

    @Test fun realDeviceCapsuleUsesNonexportablePerOperationKey() {
        try { verifyPolicy() }
        catch (error: Throwable) {
            // Instrumentation output is private, but even there avoid printing
            // arbitrary provider messages, aliases, file names or causes.
            instrumentation.sendStatus(0, Bundle().apply {
                putString("locklark_key_stage", stage)
                putString("locklark_key_assertion", assertion)
                putString("locklark_key_exception", if (error is AssertionError) "assertion" else NativeFailures.exceptionKind(error).name.lowercase())
                val source = error.stackTrace.filter { it.className == DeviceKeyProtectionTest::class.java.name && it.fileName == "DeviceKeyProtectionTest.kt" }
                val line = (source.firstOrNull { it.methodName == "verifyPolicy" } ?: source.firstOrNull())?.lineNumber ?: 0
                putString("locklark_key_source_line", if (line in 1..99999) line.toString() else "0")
                metadata.forEach { (name, value) -> putString(name, value) }
            })
            throw AssertionError("Device key policy verification failed")
        }
    }

    private fun verifyPolicy() {
        report("installation")
        val root = File(instrumentation.targetContext.noBackupFilesDir,"device-unlock")
        val install = File(root,"installation").readText()
        policy("installation", "installation-format", install.matches(Regex("[0-9a-f-]{36}")))
        report("capsule-selection")
        val capsules = root.listFiles()!!.filter { it.name.matches(Regex("[0-9a-f]{64}\\.capsule")) }
        policy("capsule-selection", "one-capsule", capsules.size == 1)
        val capsule = capsules.single()
        report("permissions")
        policy("permissions", "capsule-mode", Os.stat(capsule.path).st_mode and 511 == 384)
        policy("permissions", "directory-mode", Os.stat(root.path).st_mode and 511 == 448)
        report("envelope")
        val envelope = capsule.readBytes()
        try {
            policy("envelope", "envelope-size", envelope.size >= 36)
            val header = ByteBuffer.wrap(envelope)
            policy("envelope", "envelope-format", header.int == 1 && header.int == 12)
        } finally { envelope.fill(0) }
        report("key-load")
        val alias = "org.locklark.android.$install." + capsule.name.removeSuffix(".capsule")
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = store.getKey(alias,null) as SecretKey
        val encoded = key.encoded
        metadata["locklark_key_nonexportable"] = (encoded == null).toString()
        try { policy("nonexportable", "nonexportable", encoded == null) } finally { encoded?.fill(0) }
        report("key-info")
        val info = SecretKeyFactory.getInstance("AES","AndroidKeyStore").getKeySpec(key,KeyInfo::class.java) as KeyInfo
        val validity = info.userAuthenticationValidityDurationSeconds
        metadata["locklark_key_auth_required"] = info.isUserAuthenticationRequired.toString()
        metadata["locklark_key_auth_validity"] = if (validity in -1..86400) validity.toString() else "out-of-range"
        metadata["locklark_key_cipher_exact"] = DeviceKeyPolicyOracle.exactCipher(
            info.keySize, info.blockModes.toSet(), info.encryptionPaddings.toSet(), info.purposes).toString()
        metadata["locklark_key_auth_types_exact"] = (info.userAuthenticationType == (KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)).toString()
        val level = if (Build.VERSION.SDK_INT >= 31) when(info.securityLevel) {
            0 -> "software"; 1 -> "tee"; 2 -> "strongbox"; else -> "unknown"
        } else if (info.isInsideSecureHardware) "hardware-unspecified" else "software"
        instrumentation.sendStatus(0,Bundle().apply { putString("locklark_key_level",level) })
        policy("auth-required", "auth-required", info.isUserAuthenticationRequired)
        // Android 15 KeyStore2 reports 0 when AUTH_TIMEOUT is absent. The
        // older KeyInfo API documents -1. Neither permits a timed auth window.
        policy("auth-validity", "per-operation", validity == -1 || validity == 0)
        policy("cipher-policy", "aes256-gcm", metadata["locklark_key_cipher_exact"] == "true")
        policy("auth-types", "exact-auth-types", metadata["locklark_key_auth_types_exact"] == "true")
        // A fresh operation has never been given to BiometricPrompt. A previous
        // successful PIN must not make this different operation usable.
        var denial = AuthenticationDenial.NONE
        try {
            report("fresh-init")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE,key)
            report("fresh-aad")
            cipher.updateAAD("public unauthenticated AAD probe".toByteArray())
            report("fresh-finish")
            cipher.doFinal("public unauthenticated probe".toByteArray()).fill(0)
        } catch (error: Exception) {
            denial = DeviceKeyPolicyOracle.authenticationDenial(error, ::authenticationFacts)
            metadata["locklark_key_fresh_denial"] = denial.name.lowercase()
            metadata["locklark_key_fresh_rejected"] = (denial != AuthenticationDenial.NONE).toString()
            if (denial == AuthenticationDenial.NONE) throw error
        }
        val rejected = denial != AuthenticationDenial.NONE
        metadata["locklark_key_fresh_denial"] = denial.name.lowercase()
        metadata["locklark_key_fresh_rejected"] = rejected.toString()
        policy("fresh-rejection", "fresh-unauthenticated-rejected", rejected)
        report("complete")
    }
}

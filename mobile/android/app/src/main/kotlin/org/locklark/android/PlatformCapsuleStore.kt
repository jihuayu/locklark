package org.locklark.android

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class PlatformAuthenticationFailure : Exception("Native authentication unavailable or cancelled")

/** A single explicitly initiated OS-authenticated operation; no plaintext cache. */
class NativeCryptoPrompt(private val activity: Activity, private val current: () -> Boolean) {
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var cancellation: CancellationSignal? = null
    @Volatile private var completion: CompletableFuture<Cipher>? = null

    fun authenticate(cipher: Cipher): Cipher {
        check(Looper.myLooper() != Looper.getMainLooper())
        val result = CompletableFuture<Cipher>()
        val signal = CancellationSignal()
        completion = result
        cancellation = signal
        main.post {
            if (!current() || result.isDone) {
                result.completeExceptionally(PlatformAuthenticationFailure())
            } else {
                try {
                    BiometricPrompt.Builder(activity)
                        .setTitle("认证此设备以解封本地金库授权")
                        .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                        .build()
                        .authenticate(BiometricPrompt.CryptoObject(cipher), signal, activity.mainExecutor,
                            object : BiometricPrompt.AuthenticationCallback() {
                                override fun onAuthenticationSucceeded(value: BiometricPrompt.AuthenticationResult) {
                                    val authorized = value.cryptoObject?.cipher
                                    if (current() && authorized != null) result.complete(authorized)
                                    else result.completeExceptionally(PlatformAuthenticationFailure())
                                }
                                override fun onAuthenticationError(code: Int, message: CharSequence?) {
                                    result.completeExceptionally(PlatformAuthenticationFailure())
                                }
                            })
                } catch (_: Exception) {
                    result.completeExceptionally(PlatformAuthenticationFailure())
                }
            }
        }
        try {
            val authorized = result.get(60, TimeUnit.SECONDS)
            if (!current()) throw PlatformAuthenticationFailure()
            return authorized
        } catch (_: Exception) {
            throw PlatformAuthenticationFailure()
        } finally {
            signal.cancel()
            if (completion === result) { completion = null; cancellation = null }
        }
    }

    fun cancel() {
        completion?.completeExceptionally(PlatformAuthenticationFailure())
        cancellation?.cancel()
    }
}

/** Protects the Go core's path/slot-bound capsule, never the two full factors. */
class PlatformCapsuleStore(context: Context, private val prompt: NativeCryptoPrompt, private val current: () -> Boolean) {
    private val root = File(context.noBackupFilesDir, "device-unlock").apply { mkdirs(); Os.chmod(path, 448) }
    private val keyguard = context.getSystemService(KeyguardManager::class.java)
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val installation: String = run {
        val file = AtomicFile(File(root, "installation"))
        try { file.openRead().bufferedReader().use { it.readText() }.also { require(it.matches(Regex("[0-9a-f-]{36}"))) } }
        catch (_: java.io.FileNotFoundException) {
            UUID.randomUUID().toString().also { value -> atomicWrite(file, value.toByteArray()) }
        }
    }

    private fun name(id: String): String {
        if (id.isEmpty() || id.length > 4096) throw PlatformAuthenticationFailure()
        return MessageDigest.getInstance("SHA-256").digest(id.toByteArray()).joinToString("") { "%02x".format(it) }
    }
    private fun alias(id: String) = "org.locklark.android.$installation.${name(id)}"
    private fun file(id: String) = AtomicFile(File(root, name(id) + ".capsule"))
    private fun aad(id: String) = ("locklark.android.capsule.v1\u0000" + id).toByteArray(Charsets.UTF_8)
    private fun ready() {
        if (!current() || !keyguard.isDeviceSecure) throw PlatformAuthenticationFailure()
    }

    private fun key(id: String, create: Boolean): SecretKey {
        val existing = keys.getKey(alias(id), null)
        if (existing is SecretKey) return existing
        if (!create) throw PlatformAuthenticationFailure()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias(id), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .setInvalidatedByBiometricEnrollment(true)
            .build())
        return generator.generateKey()
    }

    fun store(id: String, value: ByteArray) {
        try {
            ready()
            if (value.isEmpty() || value.size > 1_048_576) throw PlatformAuthenticationFailure()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key(id, true))
            cipher.updateAAD(aad(id))
            val authenticated = prompt.authenticate(cipher)
            ready()
            val encrypted = authenticated.doFinal(value)
            try {
                val iv = authenticated.iv
                if (iv.size != 12) throw PlatformAuthenticationFailure()
                val envelope = ByteBuffer.allocate(8 + iv.size + encrypted.size)
                    .putInt(1).putInt(iv.size).put(iv).put(encrypted).array()
                try { ready(); atomicWrite(file(id), envelope); ready() } finally { envelope.fill(0) }
            } finally { encrypted.fill(0) }
        } catch (_: Exception) {
            // Failed writes cannot silently retain an earlier quick-unlock grant.
            runCatching { file(id).delete() }
            throw PlatformAuthenticationFailure()
        } finally { value.fill(0) }
    }

    fun load(id: String): ByteArray {
        var envelope = ByteArray(0)
        try {
            ready()
            envelope = file(id).openRead().use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > 1_048_628) throw PlatformAuthenticationFailure()
                    output.write(buffer, 0, count)
                }
                buffer.fill(0)
                output.toByteArray()
            }
            if (envelope.size < 36) throw PlatformAuthenticationFailure()
            val data = ByteBuffer.wrap(envelope)
            if (data.int != 1 || data.int != 12) throw PlatformAuthenticationFailure()
            val iv = ByteArray(12).also { data.get(it) }
            val ciphertext = ByteArray(data.remaining()).also { data.get(it) }
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key(id, false), GCMParameterSpec(128, iv))
                cipher.updateAAD(aad(id))
                val authenticated = prompt.authenticate(cipher)
                ready()
                val plaintext = authenticated.doFinal(ciphertext)
                if (!current()) { plaintext.fill(0); throw PlatformAuthenticationFailure() }
                return plaintext
            } finally { iv.fill(0); ciphertext.fill(0) }
        } catch (_: Exception) {
            throw PlatformAuthenticationFailure()
        } finally { envelope.fill(0) }
    }

    fun delete(id: String) {
        try { file(id).delete(); keys.deleteEntry(alias(id)) }
        catch (_: Exception) { throw PlatformAuthenticationFailure() }
    }

    private fun atomicWrite(file: AtomicFile, value: ByteArray) {
        val output = file.startWrite()
        try {
            Os.fchmod(output.fd, 384)
            output.write(value)
            file.finishWrite(output)
            val committed = Os.stat(file.baseFile.path)
            if (committed.st_mode and 511 != 384 || committed.st_size != value.size.toLong()) {
                file.delete()
                throw PlatformAuthenticationFailure()
            }
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
    }
}

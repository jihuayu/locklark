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
import org.locklark.android.security.NativeAuthError
import org.locklark.android.security.NativeCallFailure
import org.locklark.android.security.NativeFailureCode
import org.locklark.android.security.NativeFailures
import org.locklark.android.security.NativePhase
import org.locklark.android.security.PerUseCrypto
import org.locklark.android.security.PerUseCryptoOperation

class PlatformAuthenticationFailure(val failure: NativeCallFailure = NativeCallFailure(NativePhase.DEVICE_READY, NativeFailureCode.UNAVAILABLE)) :
    Exception("Native authentication unavailable or cancelled")

private inline fun <T> deviceStage(phase: NativePhase, action: () -> T): T = try { action() }
    catch (error: Exception) {
        throw error as? PlatformAuthenticationFailure ?: PlatformAuthenticationFailure(
            NativeCallFailure(phase, NativeFailureCode.UNAVAILABLE, NativeFailures.exceptionKind(error)))
    }

private fun cancelledPrompt() = PlatformAuthenticationFailure(NativeCallFailure(NativePhase.DEVICE_PROMPT, NativeFailureCode.CANCELLED))

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
                result.completeExceptionally(cancelledPrompt())
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
                                    if (current() && authorized === cipher) result.complete(authorized)
                                    else result.completeExceptionally(cancelledPrompt())
                                }
                                override fun onAuthenticationError(code: Int, message: CharSequence?) {
                                    val category = NativeFailures.authError(code)
                                    val refused = if (category in setOf(NativeAuthError.CANCELLED, NativeAuthError.USER_CANCELLED,
                                            NativeAuthError.NEGATIVE_BUTTON)) NativeFailureCode.CANCELLED else NativeFailureCode.UNAVAILABLE
                                    result.completeExceptionally(PlatformAuthenticationFailure(NativeCallFailure(
                                        NativePhase.DEVICE_PROMPT, refused, authError = category)))
                                }
                            })
                } catch (error: Exception) {
                    result.completeExceptionally(PlatformAuthenticationFailure(NativeCallFailure(
                        NativePhase.DEVICE_PROMPT, NativeFailureCode.UNAVAILABLE, NativeFailures.exceptionKind(error))))
                }
            }
        }
        try {
            val authorized = result.get(60, TimeUnit.SECONDS)
            if (!current()) throw cancelledPrompt()
            return authorized
        } catch (error: Exception) {
            val original = if (error is java.util.concurrent.ExecutionException) error.cause else error
            throw original as? PlatformAuthenticationFailure ?: PlatformAuthenticationFailure(NativeCallFailure(
                NativePhase.DEVICE_WAIT, NativeFailureCode.UNAVAILABLE, NativeFailures.exceptionKind(error)))
        } finally {
            signal.cancel()
            if (completion === result) { completion = null; cancellation = null }
        }
    }

    fun cancel() {
        completion?.completeExceptionally(cancelledPrompt())
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

    private fun key(id: String, create: Boolean): SecretKey = deviceStage(NativePhase.DEVICE_KEY) {
        val existing = keys.getKey(alias(id), null)
        if (existing is SecretKey) return@deviceStage existing
        if (!create) throw PlatformAuthenticationFailure()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias(id), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .setInvalidatedByBiometricEnrollment(true)
            .build())
        generator.generateKey()
    }

    private fun authenticatedFinal(cipher: Cipher, id: String, value: ByteArray): ByteArray =
        PerUseCrypto.finish(::ready, object : PerUseCryptoOperation {
            private var authorized = cipher
            override fun authenticate() { authorized = prompt.authenticate(cipher) }
            override fun addAuthenticatedData() = deviceStage(NativePhase.DEVICE_AAD) { authorized.updateAAD(aad(id)) }
            override fun finish(): ByteArray = deviceStage(NativePhase.DEVICE_CRYPTO) { authorized.doFinal(value) }
        })

    fun store(id: String, value: ByteArray) {
        try {
            ready()
            if (value.isEmpty() || value.size > 1_048_576) throw PlatformAuthenticationFailure()
            val cipher = deviceStage(NativePhase.DEVICE_CIPHER) {
                Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key(id, true)) }
            }
            val encrypted = authenticatedFinal(cipher, id, value)
            try {
                val iv = cipher.iv
                if (iv.size != 12) throw PlatformAuthenticationFailure()
                val envelope = ByteBuffer.allocate(8 + iv.size + encrypted.size)
                    .putInt(1).putInt(iv.size).put(iv).put(encrypted).array()
                try { ready(); deviceStage(NativePhase.DEVICE_WRITE) { atomicWrite(file(id), envelope) }; ready() } finally { envelope.fill(0) }
            } finally { encrypted.fill(0) }
        } catch (error: Exception) {
            // Failed writes cannot silently retain an earlier quick-unlock grant.
            runCatching { file(id).delete() }
            throw error as? PlatformAuthenticationFailure ?: PlatformAuthenticationFailure(NativeCallFailure(
                NativePhase.DEVICE_WRITE, NativeFailureCode.UNAVAILABLE, NativeFailures.exceptionKind(error)))
        } finally { value.fill(0) }
    }

    fun load(id: String): ByteArray {
        var envelope = ByteArray(0)
        try {
            ready()
            envelope = deviceStage(NativePhase.DEVICE_READ) { file(id).openRead().use { input ->
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
            } }
            if (envelope.size < 36) throw PlatformAuthenticationFailure()
            val data = ByteBuffer.wrap(envelope)
            if (data.int != 1 || data.int != 12) throw PlatformAuthenticationFailure()
            val iv = ByteArray(12).also { data.get(it) }
            val ciphertext = ByteArray(data.remaining()).also { data.get(it) }
            try {
                val cipher = deviceStage(NativePhase.DEVICE_CIPHER) {
                    Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(id, false), GCMParameterSpec(128, iv)) }
                }
                val plaintext = authenticatedFinal(cipher, id, ciphertext)
                if (!current()) { plaintext.fill(0); throw PlatformAuthenticationFailure() }
                return plaintext
            } finally { iv.fill(0); ciphertext.fill(0) }
        } catch (error: Exception) {
            throw error as? PlatformAuthenticationFailure ?: PlatformAuthenticationFailure(NativeCallFailure(
                NativePhase.DEVICE_READ, NativeFailureCode.UNAVAILABLE, NativeFailures.exceptionKind(error)))
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

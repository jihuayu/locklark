package org.locklark.android

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/** Explicitly selected only after the host completes real OS credential auth. */
@RunWith(AndroidJUnit4::class)
class DeviceKeyProtectionTest {
    @Test fun realDeviceCapsuleUsesNonexportablePerOperationKey() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = File(instrumentation.targetContext.noBackupFilesDir,"device-unlock")
        val install = File(root,"installation").readText()
        assertTrue("Installation metadata invalid",install.matches(Regex("[0-9a-f-]{36}")))
        val capsules = root.listFiles()!!.filter { it.name.matches(Regex("[0-9a-f]{64}\\.capsule")) }
        assertTrue("Exactly one enrolled capsule required",capsules.size == 1)
        val capsule = capsules.single()
        assertTrue("Capsule permissions invalid",Os.stat(capsule.path).st_mode and 511 == 384)
        assertTrue("Capsule directory permissions invalid",Os.stat(root.path).st_mode and 511 == 448)
        val envelope = capsule.readBytes()
        try {
            assertTrue("Encrypted capsule envelope absent",envelope.size >= 36)
            val header = ByteBuffer.wrap(envelope)
            assertTrue("Encrypted capsule envelope invalid",header.int == 1 && header.int == 12)
        } finally { envelope.fill(0) }
        val alias = "org.locklark.android.$install." + capsule.name.removeSuffix(".capsule")
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = store.getKey(alias,null) as SecretKey
        assertTrue("Device key must not be exportable",key.encoded == null)
        val info = SecretKeyFactory.getInstance("AES","AndroidKeyStore").getKeySpec(key,KeyInfo::class.java) as KeyInfo
        assertTrue("Device key must require each operation authentication",info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds == -1)
        assertTrue("Device key encryption policy invalid",info.keySize == 256 && info.blockModes.contains(KeyProperties.BLOCK_MODE_GCM))
        assertTrue("Device credential auth type absent",info.userAuthenticationType == (KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG))
        val level = if (Build.VERSION.SDK_INT >= 31) when(info.securityLevel) {
            0 -> "software"; 1 -> "tee"; 2 -> "strongbox"; else -> "unknown"
        } else if (info.isInsideSecureHardware) "hardware-unspecified" else "software"
        instrumentation.sendStatus(0,Bundle().apply { putString("locklark_key_level",level) })
        // A fresh operation has never been given to BiometricPrompt. A previous
        // successful PIN must not make this different operation usable.
        var rejected = false
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE,key)
            cipher.updateAAD("public unauthenticated AAD probe".toByteArray())
            cipher.doFinal("public unauthenticated probe".toByteArray()).fill(0)
        } catch (_: GeneralSecurityException) { rejected = true }
        assertTrue("Unauthenticated device-key operation succeeded",rejected)
    }
}

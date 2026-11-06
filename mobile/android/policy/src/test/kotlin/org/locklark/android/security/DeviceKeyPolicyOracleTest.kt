package org.locklark.android.security

import org.junit.Assert.*
import org.junit.Test
import org.locklark.android.verification.AuthenticationFailureFacts
import org.locklark.android.verification.DeviceKeyPolicyOracle
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.ProviderException
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException

class DeviceKeyPolicyOracleTest {
    private class UserAuthFailure : InvalidKeyException()
    private class KeyStoreFailure(val facts: AuthenticationFailureFacts.KeyStore) : Exception()
    private val inspect: (Throwable) -> AuthenticationFailureFacts = { error -> when (error) {
        is UserAuthFailure -> AuthenticationFailureFacts.UserNotAuthenticated
        is KeyStoreFailure -> error.facts
        else -> AuthenticationFailureFacts.Other
    } }
    private fun denied(error: Throwable) = DeviceKeyPolicyOracle.isAuthenticationDenial(error, inspect)

    @Test fun exactCipherRejectsExtraModesPaddingsAndPurposeBits() {
        assertTrue(DeviceKeyPolicyOracle.exactCipher(256, setOf("GCM"), setOf("NoPadding"), 3))
        assertFalse(DeviceKeyPolicyOracle.exactCipher(256, setOf("GCM", "CBC"), setOf("NoPadding"), 3))
        assertFalse(DeviceKeyPolicyOracle.exactCipher(256, setOf("GCM"), setOf("NoPadding", "PKCS7Padding"), 3))
        assertFalse(DeviceKeyPolicyOracle.exactCipher(256, setOf("GCM"), setOf("NoPadding"), 1))
        assertFalse(DeviceKeyPolicyOracle.exactCipher(256, setOf("GCM"), setOf("NoPadding"), 7))
        assertFalse(DeviceKeyPolicyOracle.exactCipher(128, setOf("GCM"), setOf("NoPadding"), 3))
    }

    @Test fun typedAuthenticationAndSourceBackedWrappersAreAccepted() {
        assertTrue(denied(UserAuthFailure()))
        val native = KeyStoreFailure(AuthenticationFailureFacts.KeyStore(2, true, false))
        assertTrue(denied(IllegalBlockSizeException().apply { initCause(native) }))
        assertTrue(denied(ProviderException("fixed", InvalidKeyException("fixed", native))))
    }

    @Test fun unrelatedCryptoFailuresAndLookalikeBodiesAreNeverAccepted() {
        assertFalse(denied(GeneralSecurityException("User not authenticated")))
        assertFalse(denied(ProviderException("User not authenticated")))
        assertFalse(denied(InvalidAlgorithmParameterException("fixed", UserAuthFailure())))
        assertFalse(denied(BadPaddingException("fixed").apply { initCause(UserAuthFailure()) }))
        assertFalse(denied(IllegalStateException("fixed", UserAuthFailure())))
        assertFalse(denied(object : InvalidKeyException("fixed", UserAuthFailure()) {}))
    }

    @Test fun publicKeyStoreCodeAndAuthenticationFlagsMustAllMatch() {
        for (facts in listOf(AuthenticationFailureFacts.KeyStore(1, true, false),
                             AuthenticationFailureFacts.KeyStore(2, false, false),
                             AuthenticationFailureFacts.KeyStore(2, true, true))) {
            assertFalse(denied(IllegalBlockSizeException().apply { initCause(KeyStoreFailure(facts)) }))
        }
    }

    @Test fun causeCyclesAndExcessDepthFailClosed() {
        val first = ProviderException()
        val second = ProviderException()
        first.initCause(second); second.initCause(first)
        assertFalse(denied(first))
        var within: Throwable = UserAuthFailure()
        repeat(7) { within = ProviderException("fixed", within) }
        assertTrue(denied(within))
        assertFalse(denied(ProviderException("fixed", within)))
    }
}

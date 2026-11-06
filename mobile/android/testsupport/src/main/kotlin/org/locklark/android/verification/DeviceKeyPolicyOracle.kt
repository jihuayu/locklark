package org.locklark.android.verification

import java.security.InvalidKeyException
import java.security.ProviderException
import java.util.IdentityHashMap
import javax.crypto.IllegalBlockSizeException

/** Test-only facts adapter; no Android reflection or message matching. */
sealed interface AuthenticationFailureFacts {
    data object UserNotAuthenticated : AuthenticationFailureFacts
    data class KeyStore(val code: Int, val requiresAuthentication: Boolean, val systemError: Boolean) : AuthenticationFailureFacts
    data object Other : AuthenticationFailureFacts
}
enum class AuthenticationDenial { NONE, USER_NOT_AUTHENTICATED, KEYSTORE_AUTHENTICATION_REQUIRED }

/** Compiled only into policy JVM tests and the instrumentation APK. */
object DeviceKeyPolicyOracle {
    fun exactCipher(size: Int, modes: Set<String>, paddings: Set<String>, purposes: Int): Boolean =
        size == 256 && modes == setOf("GCM") && paddings == setOf("NoPadding") && purposes == 3 // ENCRYPT(1) | DECRYPT(2)

    fun isAuthenticationDenial(error: Throwable, inspect: (Throwable) -> AuthenticationFailureFacts): Boolean =
        authenticationDenial(error, inspect) != AuthenticationDenial.NONE

    fun authenticationDenial(error: Throwable, inspect: (Throwable) -> AuthenticationFailureFacts): AuthenticationDenial {
        var current = error
        val seen = IdentityHashMap<Throwable, Boolean>()
        repeat(8) {
            if (seen.put(current, true) != null) return AuthenticationDenial.NONE
            when (val facts = inspect(current)) {
                AuthenticationFailureFacts.UserNotAuthenticated -> return AuthenticationDenial.USER_NOT_AUTHENTICATED
                is AuthenticationFailureFacts.KeyStore -> return if (facts.code == 2 && facts.requiresAuthentication && !facts.systemError) {
                    // API 33+ public ERROR_USER_AUTHENTICATION_REQUIRED == 2.
                    AuthenticationDenial.KEYSTORE_AUTHENTICATION_REQUIRED
                } else AuthenticationDenial.NONE
                AuthenticationFailureFacts.Other -> Unit
            }
            // Android 15 maps init failures to InvalidKeyException, caches AAD
            // failures and wraps them in IllegalBlockSizeException at doFinal,
            // or wraps a provider operation failure. Do not traverse arbitrary
            // RuntimeException, padding errors, invalid parameters or subclasses.
            if (current.javaClass != InvalidKeyException::class.java && current.javaClass != IllegalBlockSizeException::class.java &&
                current.javaClass != ProviderException::class.java) return AuthenticationDenial.NONE
            current = current.cause ?: return AuthenticationDenial.NONE
        }
        return AuthenticationDenial.NONE
    }
}

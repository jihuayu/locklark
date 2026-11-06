package org.locklark.android.security

import org.junit.Assert.*
import org.junit.Test

class PerUseCryptoTest {
    @Test fun perUseKeystoreReceivesNoDataBeforeAuthentication() {
        var authenticated = false
        var aad = false
        val operation = object : PerUseCryptoOperation {
            override fun authenticate() { authenticated = true }
            override fun addAuthenticatedData() { check(authenticated); aad = true }
            override fun finish(): ByteArray { check(authenticated && aad); return byteArrayOf(1) }
        }
        PerUseCrypto.finish({}, operation).fill(0)
        assertTrue(aad)
    }

    @Test fun lifecycleCancellationAfterAuthenticationNeverFeedsData() {
        var current = true
        var dataCalls = 0
        val operation = object : PerUseCryptoOperation {
            override fun authenticate() { current = false }
            override fun addAuthenticatedData() { dataCalls++ }
            override fun finish(): ByteArray { dataCalls++; return byteArrayOf(1) }
        }
        assertTrue(runCatching { PerUseCrypto.finish({ check(current) }, operation) }.isFailure)
        assertEquals(0, dataCalls)
    }

    @Test fun cancellationBeforeReturnWipesReturnedBuffer() {
        var current = true
        val output = byteArrayOf(7, 8)
        val operation = object : PerUseCryptoOperation {
            override fun authenticate() {}
            override fun addAuthenticatedData() {}
            override fun finish(): ByteArray { current = false; return output }
        }
        assertTrue(runCatching { PerUseCrypto.finish({ check(current) }, operation) }.isFailure)
        assertArrayEquals(ByteArray(2), output)
    }
}

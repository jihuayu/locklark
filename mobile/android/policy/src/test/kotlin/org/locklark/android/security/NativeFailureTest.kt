package org.locklark.android.security

import org.junit.Assert.*
import org.junit.Test

class NativeFailureTest {
    @Test fun arbitraryNativeBodiesAreNeverReturnedAsReasons() {
        val secret = "private-factor-not-for-logs"
        assertEquals(NativeFailureCode.OTHER, NativeFailures.classify(Exception(secret)))
        val failure = runCatching { NativeFailures.call(NativePhase.CREATE) { throw Exception(secret) } }.exceptionOrNull()!!
        assertTrue(failure is NativeCallFailure)
        assertFalse(failure.toString().contains(secret))
        assertNull(failure.cause)
    }
    @Test fun unknownAndCancellationKeepTheirFixedMeaning() {
        assertEquals(NativeFailureCode.UNKNOWN, NativeFailures.classify(Exception("operation result unknown; inspect the vault before retrying")))
        assertEquals(NativeFailureCode.UNKNOWN, NativeFailures.classify(Exception("go error: operation result unknown; inspect the vault before retrying")))
        assertEquals(NativeFailureCode.CANCELLED, NativeFailures.classify(ObsoleteWork()))
    }
}

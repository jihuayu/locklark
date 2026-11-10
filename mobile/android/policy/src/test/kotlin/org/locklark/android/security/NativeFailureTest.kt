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

    @Test fun deviceDiagnosticHasOnlyAllowlistedFieldsAndNoCause() {
        val privateValue = "private-alias-path-factor-body"
        val failure = NativeFailures.failure(NativePhase.DEVICE_CIPHER, IllegalStateException(privateValue))
        assertEquals("stage=DEVICE_CIPHER code=OTHER exception=ILLEGAL_STATE os=NONE", NativeFailures.diagnostic(failure))
        assertFalse(NativeFailures.diagnostic(failure).contains(privateValue))
        assertNull(failure.cause)
        assertEquals(NativeExceptionKind.OTHER, NativeFailures.exceptionKind(object : Exception(privateValue) {}))
        assertEquals(NativeAuthError.OTHER, NativeFailures.authError(999999))
        assertEquals(NativeAuthError.NO_DEVICE_CREDENTIAL, NativeFailures.authError(14))
        assertSame(failure, NativeFailures.failure(NativePhase.OPERATION, failure))
    }

    @Test fun userFacingFailureAndPhaseCopyRemainsDistinctAndNonEmpty() {
        val codeTexts = NativeFailureCode.entries.map { it.userText }
        assertTrue(codeTexts.all { it.isNotBlank() && it.endsWith("。") })
        assertEquals(codeTexts.size, codeTexts.toSet().size)
        val phaseTexts = NativePhase.entries.map { it.userText }
        assertTrue(phaseTexts.all { it.isNotBlank() })
        assertEquals(phaseTexts.size, phaseTexts.toSet().size)
    }
}

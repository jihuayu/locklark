package org.locklark.android.security

import org.junit.Assert.*
import org.junit.Test

class ReturnedSecretBuffersTest {
    @Test fun returnedCopyRemainsUsableUntilCoreReturnsThenIsCleared() {
        val owner = ReturnedSecretBuffers()
        val value = byteArrayOf(9,8,7)
        assertSame(value, owner.retain(value))
        assertTrue(value.any { it != 0.toByte() })
        owner.clearAfterCall()
        assertTrue(value.all { it == 0.toByte() })
        owner.clearAfterCall()
    }
    @Test fun callbackAfterReturnIsRejectedAndItsCopyCleared() {
        val owner = ReturnedSecretBuffers(); owner.clearAfterCall()
        val late = byteArrayOf(1,2,3)
        assertTrue(runCatching { owner.retain(late) }.exceptionOrNull() is ObsoleteWork)
        assertTrue(late.all { it == 0.toByte() })
    }
}

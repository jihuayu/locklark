package org.locklark.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The authentication sender is one-shot, updated in place and mutable exactly
 * from API 31, where FLAG_MUTABLE exists; API 30 must never receive it.
 */
class AutofillPendingIntentFlagsTest {
    private val mutable = 1 shl 25 // PendingIntent.FLAG_MUTABLE

    @Test
    fun api30NeverReceivesTheMutableFlag() {
        val flags = AutofillPendingIntentFlags.flags(30)
        assertEquals(0, flags and mutable)
        assertTrue("one-shot", flags and (1 shl 30) != 0) // FLAG_ONE_SHOT
        assertTrue("update current", flags and (1 shl 27) != 0) // FLAG_UPDATE_CURRENT
    }

    @Test
    fun api31AndLaterUseTheExplicitOneShotMutableSender() {
        for (api in 31..36) {
            val flags = AutofillPendingIntentFlags.flags(api)
            assertEquals("API $api must be mutable (FLAG_MUTABLE exists from 31)", mutable, flags and mutable)
            assertTrue("API $api one-shot", flags and (1 shl 30) != 0)
            assertEquals("the mutable sender never adds an immutable flag", 0, flags and (1 shl 26))
        }
    }

    @Test
    fun theGuardMatchesThePlatformMutabilityBoundary() {
        assertEquals(31, AutofillPendingIntentFlags.MUTABLE_API)
    }
}

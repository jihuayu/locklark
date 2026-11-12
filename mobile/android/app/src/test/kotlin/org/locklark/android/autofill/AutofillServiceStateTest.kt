package org.locklark.android.autofill

import android.service.autofill.FillResponse
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/** Reviewed-response replay/take policy with an injected clock. */
class AutofillServiceStateTest {
    private val now = 10_000L

    @After
    fun clearState() {
        AutofillServiceState.clear()
    }

    @Test
    fun aReviewedResponseIsPeekedUntilTakenExactlyOnce() {
        val response = FillResponse()
        AutofillServiceState.remember("nonce-1", response, now)
        assertSame(response, AutofillServiceState.peek("nonce-1", now))
        assertSame("peek never consumes", response, AutofillServiceState.peek("nonce-1", now))
        assertSame(response, AutofillServiceState.take("nonce-1", now))
        assertNull("an authentication result is one-use", AutofillServiceState.take("nonce-1", now))
        assertNull(AutofillServiceState.peek("nonce-1", now))
        assertEquals(0, AutofillServiceState.count())
    }

    @Test
    fun anExpiredResponseIsNeverReturned() {
        AutofillServiceState.remember("nonce-1", FillResponse(), now)
        assertNull(AutofillServiceState.take("nonce-1", now + AutofillServiceState.REVIEWED_TTL_MS + 1))
        assertEquals(0, AutofillServiceState.count())
    }

    @Test
    fun theCacheIsBoundedAndReplacesADuplicateKey() {
        val first = FillResponse()
        val replacement = FillResponse()
        AutofillServiceState.remember("nonce-1", first, now)
        AutofillServiceState.remember("nonce-1", replacement, now)
        assertEquals(1, AutofillServiceState.count())
        assertSame(replacement, AutofillServiceState.peek("nonce-1", now))

        for (index in 0 until AutofillServiceState.MAX_REVIEWED + 3) {
            AutofillServiceState.remember("nonce-$index", FillResponse(), now)
        }
        assertEquals(AutofillServiceState.MAX_REVIEWED, AutofillServiceState.count())
        assertNull("the oldest response is evicted", AutofillServiceState.peek("nonce-1", now))
        assertNotNull(AutofillServiceState.peek("nonce-" + (AutofillServiceState.MAX_REVIEWED + 2), now))
    }

    @Test
    fun anUnmeasurableResponseIsNeverCached() {
        AutofillServiceState.remember("nonce-1", FillResponse(), now) { null }
        assertEquals(0, AutofillServiceState.count())
        assertNull(
            "an unmeasured response must never be treated as zero bytes",
            AutofillServiceState.take("nonce-1", now),
        )
    }

    @Test
    fun anUnmeasuredReplacementIsNotKeptUnderItsKey() {
        AutofillServiceState.remember("nonce-1", FillResponse(), now) { 16 }
        val unmeasured = FillResponse()
        AutofillServiceState.remember("nonce-1", unmeasured, now) { null }
        assertNotSame("the unmeasured response is never stored", unmeasured, AutofillServiceState.take("nonce-1", now))
    }

    @Test
    fun aResponseOverCapacityIsNeverCached() {
        AutofillServiceState.remember("nonce-1", FillResponse(), now) { AutofillServiceState.REVIEWED_CAPACITY + 1 }
        assertNull(AutofillServiceState.take("nonce-1", now))
        AutofillServiceState.remember("nonce-2", FillResponse(), now) { AutofillServiceState.REVIEWED_CAPACITY }
        assertNotNull("exactly at capacity is still cached", AutofillServiceState.take("nonce-2", now))
    }

    @Test
    fun clearingDropsEveryReviewedResponse() {
        AutofillServiceState.remember("a", FillResponse(), now)
        AutofillServiceState.remember("b", FillResponse(), now)
        AutofillServiceState.clear()
        assertEquals(0, AutofillServiceState.count())
        assertNull(AutofillServiceState.peek("a", now))
    }
}

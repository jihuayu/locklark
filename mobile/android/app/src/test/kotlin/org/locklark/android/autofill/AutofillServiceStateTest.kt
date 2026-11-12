package org.locklark.android.autofill

import android.service.autofill.FillResponse
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * Reviewed-response replay/take and accounting policy with an injected clock
 * and synthetic measured sizes.
 */
class AutofillServiceStateTest {
    private val now = 10_000L

    private val capacity = AutofillServiceState.REVIEWED_CAPACITY

    private val sizes = HashMap<FillResponse, Int?>()

    /** Remembers [response] under [key] with the synthetic size [measuredSize]. */
    private fun remember(
        key: String,
        response: FillResponse = FillResponse(),
        measuredSize: Int = DEFAULT_SIZE,
        at: Long = now,
    ) {
        sizes[response] = measuredSize
        AutofillServiceState.remember(key, response, at) { sizes[it] }
    }

    /** Remembers [response] under [key] with a measurement that never succeeds. */
    private fun rememberUnmeasured(key: String, response: FillResponse = FillResponse()) {
        sizes[response] = null
        AutofillServiceState.remember(key, response, now) { sizes[it] }
    }

    private fun forget(key: String) {
        AutofillServiceState.forget(key)
    }

    private fun peek(key: String, at: Long = now) = AutofillServiceState.peek(key, at)

    private fun take(key: String, at: Long = now) = AutofillServiceState.take(key, at)

    private fun count() = AutofillServiceState.count()

    private fun bytes() = AutofillServiceState.bytes()

    /** The synthetic size of the response cached under [key], or null. */
    private fun cachedSize(key: String): Int? = peek(key)?.let { sizes[it] }

    @After
    fun clearState() {
        AutofillServiceState.clear()
        sizes.clear()
    }

    @Test
    fun aReviewedResponseIsPeekedUntilTakenExactlyOnce() {
        val response = FillResponse()
        remember("nonce-1", response)
        assertSame(response, peek("nonce-1"))
        assertSame("peek never consumes", response, peek("nonce-1"))
        assertSame(response, take("nonce-1"))
        assertNull("an authentication result is one-use", take("nonce-1"))
        assertNull(peek("nonce-1"))
        assertEquals(0, count())
        assertEquals(0, bytes())
    }

    @Test
    fun anExpiredResponseIsNeverReturned() {
        remember("nonce-1", measuredSize = 16)
        assertEquals(16, bytes())
        val later = now + AutofillServiceState.REVIEWED_TTL_MS + 1
        assertNull(take("nonce-1", later))
        assertEquals(0, count())
        assertEquals("an expired response releases its bytes", 0, bytes())
    }

    @Test
    fun aResponseStaysUntilItsTtlExpires() {
        remember("nonce-1", measuredSize = 16)
        val stillFresh = now + AutofillServiceState.REVIEWED_TTL_MS
        assertNotNull("the TTL boundary is still fresh", peek("nonce-1", stillFresh))
        assertEquals(1, count())
        assertEquals(16, bytes())
    }

    @Test
    fun theCountBoundEvictsTheOldestResponseAndReplacesADuplicateKey() {
        val first = FillResponse()
        val replacement = FillResponse()
        remember("nonce-1", first)
        remember("nonce-1", replacement)
        assertEquals(1, count())
        assertSame(replacement, peek("nonce-1"))

        for (index in 0 until AutofillServiceState.MAX_REVIEWED + 3) {
            remember("nonce-$index")
        }
        assertEquals(AutofillServiceState.MAX_REVIEWED, count())
        assertNull("the oldest response is evicted", peek("nonce-1"))
        assertNotNull(peek("nonce-" + (AutofillServiceState.MAX_REVIEWED + 2)))
        assertEquals(AutofillServiceState.MAX_REVIEWED * DEFAULT_SIZE, bytes())
    }

    @Test
    fun theAggregateBytesEvictTheOldestResponseUntilTheNewOneFits() {
        val quarter = capacity / 4
        remember("a", measuredSize = quarter)
        remember("b", measuredSize = quarter)
        remember("c", measuredSize = quarter)
        assertEquals(3 * quarter, bytes())

        // A fourth quarter reaches exactly the capacity: nothing is evicted.
        remember("d", measuredSize = quarter)
        assertEquals(4, count())
        assertEquals(capacity, bytes())

        // One more byte evicts the oldest response, and only that one.
        remember("e", measuredSize = 1)
        assertNull("the oldest response is evicted for size", peek("a"))
        assertEquals(quarter, cachedSize("b"))
        assertEquals(quarter, cachedSize("d"))
        assertEquals(1, cachedSize("e"))
        assertEquals(3 * quarter + 1, bytes())

        // A large response evicts the oldest responses until it fits.
        remember("f", measuredSize = 3 * quarter)
        assertNull(peek("b"))
        assertNull(peek("c"))
        assertEquals(3 * quarter, cachedSize("f"))
        assertEquals(3 * quarter + 1, bytes())

        // A response larger than the whole capacity is never cached.
        remember("g", measuredSize = capacity + 1)
        assertNull(peek("g"))
        assertEquals("an oversized response evicts nothing", 3 * quarter + 1, bytes())
    }

    @Test
    fun bothBoundsHoldAcrossAMixedStream() {
        for (index in 0 until 40) {
            remember("stream-$index", measuredSize = capacity / 6)
            assertEquals(bytes(), (0 until 40).mapNotNull { cachedSize("stream-$it") }.sum())
            assertEquals(minOf(index + 1, capacity / (capacity / 6)), count())
        }
        assertEquals("only the newest responses fit", 6, count())
        assertEquals(6 * (capacity / 6), bytes())
        assertNull(peek("stream-33"))
        assertNotNull(peek("stream-34"))
        assertNotNull(peek("stream-39"))
        assertEquals(6 * (capacity / 6), (34..39).mapNotNull { cachedSize("stream-$it") }.sum())
    }

    @Test
    fun aReplacementIsAccountedByItsOwnSize() {
        val half = capacity / 2
        remember("a", measuredSize = half)
        remember("b", measuredSize = half)
        assertEquals(capacity, bytes())

        // A smaller replacement frees room without any eviction.
        remember("a", measuredSize = 1)
        assertEquals(2, count())
        assertEquals(1, cachedSize("a"))
        assertEquals(half, cachedSize("b"))
        assertEquals(half + 1, bytes())

        // Growing it back to half fits beside "b" at exactly capacity.
        remember("a", measuredSize = half)
        assertEquals(2, count())
        assertEquals(capacity, bytes())

        // Growing it further evicts only the older "b", never "a" itself.
        remember("a", measuredSize = capacity - 1)
        assertEquals(1, count())
        assertEquals(capacity - 1, cachedSize("a"))
        assertNull(peek("b"))
        assertEquals(capacity - 1, bytes())
    }

    @Test
    fun anExactlyCapacityResponseIsAdmitted() {
        remember("a", measuredSize = capacity - 1)
        remember("b", measuredSize = 1)
        assertEquals(capacity, bytes())

        remember("a", measuredSize = capacity)
        assertEquals("exactly at capacity is cached", capacity, cachedSize("a"))
        assertEquals(1, count())
        assertNull("the other entry made room", peek("b"))
        assertEquals(capacity, bytes())

        remember("b", measuredSize = 1)
        assertEquals(1, count())
        assertEquals(1, cachedSize("b"))
        assertEquals(1, bytes())
    }

    @Test
    fun aStandaloneExactlyCapacityResponseIsAdmitted() {
        remember("exact", measuredSize = capacity)
        assertEquals(capacity, cachedSize("exact"))
        assertEquals(capacity, bytes())
        remember("over", measuredSize = 1)
        assertNull("the exact response made room", peek("exact"))
        assertEquals(1, cachedSize("over"))
    }

    @Test
    fun anUnmeasurableResponseIsNeverCached() {
        rememberUnmeasured("nonce-1")
        assertEquals(0, count())
        assertEquals(0, bytes())
        assertNull(
            "an unmeasured response must never be treated as zero bytes",
            take("nonce-1"),
        )
    }

    @Test
    fun aNegativeResponseIsNeverCached() {
        remember("nonce-1", measuredSize = -1)
        assertEquals(0, count())
        assertEquals(0, bytes())
        assertNull(take("nonce-1"))
    }

    @Test
    fun anUnmeasuredReplacementDropsTheStaleResponseUnderItsKey() {
        remember("nonce-1", measuredSize = 16)
        val unmeasured = FillResponse()
        rememberUnmeasured("nonce-1", unmeasured)
        assertNull("an unmeasured response is never returned", take("nonce-1"))
        assertNull("the stale response is not kept under its key", peek("nonce-1"))
        assertEquals(0, count())
        assertEquals("the stale bytes are released", 0, bytes())
    }

    @Test
    fun anOversizedResponseIsNeverCached() {
        remember("nonce-1", measuredSize = capacity + 1)
        assertNull(take("nonce-1"))
        assertEquals(0, count())
        assertEquals(0, bytes())
        remember("nonce-2", measuredSize = capacity)
        assertNotNull("exactly at capacity is still cached", take("nonce-2"))
    }

    @Test
    fun anUnmeasurableReplacementDoesNotEvictUnrelatedEntries() {
        remember("a", measuredSize = 100)
        remember("b", measuredSize = 100)
        val stored = peek("a")
        rememberUnmeasured("a")
        assertNotSame("the unmeasured response is never stored", stored, peek("a"))
        assertNull("the stale response is not kept under its key", peek("a"))
        assertEquals("nothing unrelated is evicted", 100, cachedSize("b"))
        assertEquals(1, count())
        assertEquals(100, bytes())
    }

    @Test
    fun anOversizedReplacementDoesNotEvictUnrelatedEntries() {
        remember("a", measuredSize = 100)
        remember("b", measuredSize = 100)
        remember("a", measuredSize = capacity + 1)
        assertNull("the stale response is not kept under its key", peek("a"))
        assertEquals("nothing unrelated is evicted", 100, cachedSize("b"))
        assertEquals(1, count())
        assertEquals(100, bytes())
    }

    @Test
    fun anOversizedDuplicateOfTheOnlyEntryLeavesTheCacheEmpty() {
        remember("a", measuredSize = 100)
        remember("a", measuredSize = capacity + 1)
        assertEquals(0, count())
        assertEquals(0, bytes())
    }

    @Test
    fun takeReleasesTheBytesItHeldExactlyOnce() {
        val tenth = capacity / 10
        remember("take", measuredSize = tenth)
        remember("other", measuredSize = tenth)
        assertEquals(2 * tenth, bytes())

        assertNotNull(take("take"))
        assertEquals(tenth, bytes())
        assertNull("taking twice releases nothing more", take("take"))
        assertEquals("the other bytes are untouched", tenth, bytes())
        assertEquals(1, count())

        // The released room is really available: nine tenths fit beside the
        // remaining tenth at exactly the capacity.
        remember("full", measuredSize = capacity - tenth)
        assertEquals(2, count())
        assertEquals(capacity, bytes())
        remember("overflow", measuredSize = 1)
        assertNull("the oldest entry made room", peek("other"))
        assertEquals(capacity - tenth + 1, bytes())
    }

    @Test
    fun forgetReleasesTheBytesItHeldExactlyOnce() {
        val tenth = capacity / 10
        remember("forget", measuredSize = tenth)
        remember("other", measuredSize = tenth)
        assertEquals(2 * tenth, bytes())

        forget("forget")
        forget("forget")
        forget("missing")
        assertEquals(tenth, bytes())
        assertEquals(1, count())

        // The released room is really available: nine tenths fit beside the
        // remaining tenth at exactly the capacity.
        remember("full", measuredSize = capacity - tenth)
        assertEquals(2, count())
        assertEquals(capacity, bytes())
        remember("overflow", measuredSize = 1)
        assertNull("the oldest entry made room", peek("other"))
        assertEquals(capacity - tenth + 1, bytes())
    }

    @Test
    fun anExpiredEntryReleasesItsBytesAndItsRoom() {
        val tenth = capacity / 10
        remember("expire", measuredSize = tenth)
        assertEquals(tenth, bytes())

        // The entry is only pruned by an access, which releases its bytes.
        val later = now + AutofillServiceState.REVIEWED_TTL_MS + 1
        assertNull("the expired entry is never returned", peek("expire", later))
        assertEquals("the expired entry was pruned", 0, count())
        assertEquals(0, bytes())

        // The released room is really available: nine tenths fit beside
        // another tenth, and one more byte evicts the oldest entry.
        remember("keep", measuredSize = tenth, at = later)
        assertEquals("nothing was evicted", 1, count())
        remember("full", measuredSize = capacity - tenth - 8, at = later)
        assertEquals("nothing was evicted", 2, count())
        assertEquals(capacity - 8, bytes())
        remember("overflow", measuredSize = 9, at = later)
        assertNull("the oldest entry made room", peek("keep", later))
        assertEquals(capacity - 8 - tenth + 9, bytes())
    }

    @Test
    fun clearingDropsEveryReviewedResponseAndItsBytes() {
        remember("a", measuredSize = 8)
        rememberUnmeasured("b")
        remember("c", measuredSize = 8)
        assertEquals(16, bytes())
        AutofillServiceState.clear()
        assertEquals(0, count())
        assertEquals(0, bytes())
        assertNull(peek("a"))

        // The cleared bytes leave the whole capacity available again.
        remember("d", measuredSize = capacity)
        assertEquals(capacity, cachedSize("d"))
        assertEquals(capacity, bytes())
    }

    private companion object {
        /** The synthetic measured size of an ordinary helper call. */
        const val DEFAULT_SIZE = 8
    }
}

package org.locklark.android.autofill

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The BOUND handoff retirement at positive approval: exactly the claimed token,
 * client nonce, package and the two OS AutofillIds consume the one-use record,
 * once; every refused, replayed, wrong-target/wrong-id or malformed/missing
 * binding argument retires it without ever succeeding. Ids and tokens are
 * synthetic; no platform call is made.
 */
class AutofillPositiveApprovalTest {
    private var now = 5_000L

    private val otherPackage = "com.example.otherapp"
    private val usernameId = TestAutofillIds.fresh()
    private val passwordId = TestAutofillIds.fresh()
    private val form = LoginForm(otherPackage, usernameId, passwordId)

    @Before
    fun bindClock() {
        AutofillHandoff.clock = { now }
        AutofillHandoff.clear()
    }

    @After
    fun reset() {
        AutofillHandoff.clear()
        AutofillHandoff.clock = { android.os.SystemClock.elapsedRealtime() }
    }

    /** A created handoff already claimed (BOUND) by its one Activity launch. */
    private fun bound(): AutofillHandoff.Handoff =
        AutofillHandoff.create(form).also {
            assertTrue(AutofillHandoff.claim(it.token, it.clientNonce, form))
        }

    @Test
    fun positiveApprovalConsumesTheExactBoundHandoffOnce() {
        val handoff = bound()
        assertTrue(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
        assertNull("a consumed handoff leaves no record", AutofillHandoff.state(handoff.token))
        // Replay of the exact same arguments can never produce a second fill.
        assertFalse(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun aConsumedHandoffCanNeverBeReclaimed() {
        val handoff = bound()
        assertTrue(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
        assertFalse(AutofillHandoff.claim(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun aWrongPackageRefusedAtApprovalRetiresTheRecord() {
        val handoff = bound()
        assertFalse(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form.copy(packageName = "com.example.nativeapp")))
        assertNull("a refused approval retires the record", AutofillHandoff.state(handoff.token))
        assertFalse("and it can never be retried", AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun wrongIdsRefusedAtApprovalRetireTheRecord() {
        val wrongUsername = bound()
        assertFalse(AutofillHandoff.consume(wrongUsername.token, wrongUsername.clientNonce, form.copy(usernameId = TestAutofillIds.fresh())))
        assertNull(AutofillHandoff.state(wrongUsername.token))

        val wrongPassword = bound()
        assertFalse(AutofillHandoff.consume(wrongPassword.token, wrongPassword.clientNonce, form.copy(passwordId = TestAutofillIds.fresh())))
        assertNull(AutofillHandoff.state(wrongPassword.token))

        val swapped = bound()
        assertFalse("swapped ids never consume", AutofillHandoff.consume(swapped.token, swapped.clientNonce, LoginForm(otherPackage, passwordId, usernameId)))
        assertNull(AutofillHandoff.state(swapped.token))
    }

    @Test
    fun anExpiredBoundHandoffIsRefusedAndRetired() {
        val handoff = bound()
        now += 60_001L
        assertFalse(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
        assertNull(AutofillHandoff.state(handoff.token))
    }

    @Test
    fun theClaimedNonceNamesTheOneBoundRecordWhenNoTokenIsSupplied() {
        val handoff = bound()
        assertTrue(AutofillHandoff.consume(null, handoff.clientNonce, form))
        assertNull(AutofillHandoff.state(handoff.token))
        assertFalse(AutofillHandoff.consume(null, handoff.clientNonce, form))
    }

    @Test
    fun anUnclaimedRecordIsNeverConsumed() {
        val pending = AutofillHandoff.create(form)
        assertFalse(AutofillHandoff.consume(pending.token, pending.clientNonce, form))
        assertNull("a refused unclaimed record is retired", AutofillHandoff.state(pending.token))
    }

    @Test
    fun aMissingFormStillRetiresTheSuppliedClaimedNonce() {
        val handoff = bound()
        assertFalse(AutofillHandoff.consume(handoff.token, handoff.clientNonce, null))
        assertNull("a malformed binding argument still retires the record", AutofillHandoff.state(handoff.token))
        assertFalse("it can never be replayed", AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun aMissingFormRetiresTheBoundRecordByNonceEvenWithoutAToken() {
        val handoff = bound()
        assertFalse(AutofillHandoff.consume(null, handoff.clientNonce, null))
        assertNull(AutofillHandoff.state(handoff.token))
    }

    @Test
    fun missingArgumentsRetireNothingTheyDoNotName() {
        val handoff = bound()
        // No token and no nonce cannot name the record.
        assertFalse(AutofillHandoff.consume(null, null, form))
        assertFalse(AutofillHandoff.consume(null, null, null))
        // A nonce from another handoff does not name this record.
        val other = bound()
        assertFalse(AutofillHandoff.consume(null, other.clientNonce, form.copy(usernameId = TestAutofillIds.fresh())))
        assertNull("its own nonce retired only the other record", AutofillHandoff.state(other.token))
        assertTrue("the unnamed record stays BOUND for its own exact consume", AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun anUnknownTokenOrNonceNeverConsumes() {
        val handoff = bound()
        // An unknown token names no record: it never falls back to the nonce.
        assertFalse(AutofillHandoff.consume("unknown", handoff.clientNonce, form))
        assertEquals("BOUND", AutofillHandoff.state(handoff.token))
        // An unknown nonce without a token names nothing either.
        assertFalse(AutofillHandoff.consume(null, "unknown-nonce", form))
        assertEquals("BOUND", AutofillHandoff.state(handoff.token))
        // An unknown token with the right nonce still names only the token.
        assertFalse(AutofillHandoff.consume("other-token", handoff.clientNonce, form))
        assertEquals("BOUND", AutofillHandoff.state(handoff.token))
        // Only the exact token then consumes it, once.
        assertTrue(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
        assertFalse(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun aPendingRecordIsNotRetiredByAFormlessMalformedLaunch() {
        val pending = AutofillHandoff.create(form)
        assertFalse(AutofillHandoff.consume(null, pending.clientNonce, null))
        assertTrue("the record was never claimed, so it stays pending", AutofillHandoff.claim(pending.token, pending.clientNonce, form))
        assertTrue(AutofillHandoff.consume(pending.token, pending.clientNonce, form))
    }
}

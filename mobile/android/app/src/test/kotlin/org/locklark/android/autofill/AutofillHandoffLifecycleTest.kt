package org.locklark.android.autofill

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replay/take lifecycle of the one-use handoff with an injected monotonic
 * clock. Ids are test-owned; no platform call is made.
 */
class AutofillHandoffLifecycleTest {
    private var now = 1_000L

    private val packageName = "com.example.nativeapp"
    private val usernameId = TestAutofillIds.fresh()
    private val passwordId = TestAutofillIds.fresh()
    private val form = LoginForm(packageName, usernameId, passwordId)

    private fun create() = AutofillHandoff.create(form).also {
        // Let the test drive expiry without touching the platform clock.
        now = 1_000L
    }

    @After
    fun resetClock() {
        AutofillHandoff.clear()
        AutofillHandoff.clock = { android.os.SystemClock.elapsedRealtime() }
    }

    private fun bindClock() {
        AutofillHandoff.clock = { now }
    }

    @Test
    fun claimIsOneUseAndConsumeRequiresAValidClaim() {
        bindClock()
        val handoff = create()
        assertEquals("PENDING", AutofillHandoff.state(handoff.token))
        assertTrue(AutofillHandoff.claim(handoff.token, handoff.clientNonce, form))
        assertEquals("BOUND", AutofillHandoff.state(handoff.token))
        // A configuration change or a second launch can never re-claim.
        assertFalse(AutofillHandoff.claim(handoff.token, handoff.clientNonce, form))
        assertNull(AutofillHandoff.state(handoff.token))
        // The rejected re-claim also retired the record for consumption.
        assertFalse(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun consumeIsTerminalAndExactlyOnce() {
        bindClock()
        val handoff = create()
        assertTrue(AutofillHandoff.claim(handoff.token, handoff.clientNonce, form))
        assertTrue(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
        assertFalse("a consumed handoff must never be replayed", AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
        assertNull(AutofillHandoff.state(handoff.token))
    }

    @Test
    fun anUnclaimedHandoffCanNeverBeConsumed() {
        bindClock()
        val handoff = create()
        assertFalse(AutofillHandoff.consume(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun aWrongNonceRetiresTheRecord() {
        bindClock()
        val handoff = create()
        assertFalse(AutofillHandoff.claim(handoff.token, handoff.clientNonce + "x", form))
        assertNull(AutofillHandoff.state(handoff.token))
        assertFalse("a refused intent cannot be retried", AutofillHandoff.claim(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun aPackageOrIdMismatchRetiresTheRecord() {
        bindClock()
        val wrongPackage = create()
        assertFalse(AutofillHandoff.claim(wrongPackage.token, wrongPackage.clientNonce, form.copy(packageName = "com.example.other")))
        assertFalse(AutofillHandoff.claim(wrongPackage.token, wrongPackage.clientNonce, form))

        val wrongUsername = create()
        assertFalse(AutofillHandoff.claim(wrongUsername.token, wrongUsername.clientNonce, form.copy(usernameId = TestAutofillIds.fresh())))

        val wrongPassword = create()
        assertFalse(AutofillHandoff.claim(wrongPassword.token, wrongPassword.clientNonce, form.copy(passwordId = TestAutofillIds.fresh())))
    }

    @Test
    fun theTtlCountsFromCreationAndNeverExtendsOnClaim() {
        bindClock()
        val handoff = create()
        now = 1_000L + 60_001L
        assertFalse("an expired handoff must not bind", AutofillHandoff.claim(handoff.token, handoff.clientNonce, form))
    }

    @Test
    fun discardRetiresAnyState() {
        bindClock()
        val pending = create()
        AutofillHandoff.discard(pending.token)
        assertFalse(AutofillHandoff.claim(pending.token, pending.clientNonce, form))

        val bound = create()
        assertTrue(AutofillHandoff.claim(bound.token, bound.clientNonce, form))
        AutofillHandoff.discard(bound.token)
        assertFalse(AutofillHandoff.consume(bound.token, bound.clientNonce, form))
    }

    @Test
    fun anUnknownOrNullTokenNeverClaims() {
        bindClock()
        assertFalse(AutofillHandoff.claim(null, "nonce", form))
        assertFalse(AutofillHandoff.claim("unknown", "nonce", form))
        assertFalse(AutofillHandoff.claim("unknown", null, form))
        assertFalse(AutofillHandoff.claim("unknown", "nonce", null))
    }

    @Test
    fun diagnosticsNeverExposeTheTokenNonceOrPackage() {
        bindClock()
        val handoff = create()
        assertTrue(handoff.toString(), handoff.toString().startsWith("[autofill handoff]"))
        for (secret in listOf(handoff.token, handoff.clientNonce, packageName)) {
            assertFalse(handoff.toString(), handoff.toString().contains(secret))
        }
    }
}

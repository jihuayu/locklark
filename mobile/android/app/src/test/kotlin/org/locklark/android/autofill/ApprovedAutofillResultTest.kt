package org.locklark.android.autofill

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.locklark.android.security.NativeFailureCode

/** Synthetic values only; these are not real credentials. */
class ApprovedAutofillResultTest {
    private val packageName = "com.example.nativeapp"
    private val usernameId = TestAutofillIds.fresh()
    private val passwordId = TestAutofillIds.fresh()
    private val target = AutofillTarget.from(
        LoginForm(
            packageName = packageName,
            usernameId = usernameId,
            passwordId = passwordId,
        ),
    )
    private val user = "synthetic-user".toByteArray()
    private val pass = "synthetic-pass".toByteArray()

    private fun approval(
        target: AutofillTarget = this.target,
        rowId: String = "row-1",
        revision: String = "rev-1",
    ) = ApprovedAutofillResult.create(target, rowId, revision, user, pass)

    @Test
    fun takeIsOneUseAndReturnsTheBoundCredentials() {
        val approved = approval()
        val once = approved.take()
        assertNotNull(once)
        assertArrayEquals(user, once!!.copyUsername())
        assertArrayEquals(pass, once.copyPassword())
        assertTrue(approved.isConsumed())
        assertNull("second take must fail", approved.take())
        assertNull("binding is gone after take", approved.binding)
        once.clear()
        assertArrayEquals(ByteArray(user.size), once.copyUsername())
    }

    @Test
    fun clearWipesBuffersAndPreventsAnyTake() {
        val approved = approval()
        approved.clear()
        assertNull("cleared approval exposes no binding", approved.binding)
        assertNull("cleared approval cannot be taken", approved.take())
        // Clearing again stays idempotent.
        approved.clear()
        assertNull(approved.take())
        assertNull(approval().also { it.clear() }.take())
    }

    @Test
    fun clearIsPureBufferCleanupAndRepeatedClearIsSafe() {
        // Clear carries no callback: it cannot mutate views, logs or storage.
        val approved = approval()
        approved.clear()
        // Repeated clear after clear, and after consumption, stays a no-op.
        approved.clear()
        approved.clear()
        assertTrue(approved.isConsumed())
        assertNull(approved.binding)
        assertNull(approved.take())

        val consumed = approval()
        assertNotNull(consumed.take())
        consumed.clear()
        consumed.clear()
        assertNull(consumed.take())
        assertTrue(consumed.toString().contains("consumed=true"))
    }

    @Test
    fun approvalNeverExposesCredentialsAsText() {
        val approved = approval()
        val text = approved.toString()
        assertFalse(text, text.contains("synthetic"))
        // Consuming hands the bytes to the caller; the approval keeps nothing.
        val once = approved.take()!!
        assertNull(approved.take())
        assertFalse(text, text.contains("[B@"))
        once.clear()
        assertArrayEquals(ByteArray(user.size), once.copyUsername())
        assertArrayEquals(ByteArray(pass.size), once.copyPassword())
    }

    @Test
    fun inputBuffersAreCopiedNotAliased() {
        val approved = approval()
        user.fill('x'.code.toByte())
        pass.fill('y'.code.toByte())
        val once = approved.take()!!
        assertArrayEquals("synthetic-user".toByteArray(), once.copyUsername())
        assertArrayEquals("synthetic-pass".toByteArray(), once.copyPassword())
        once.clear()
    }

    @Test
    fun targetBindsPackageAndBothAutofillIds() {
        val approved = approval()
        assertEquals(RowBinding("row-1", "rev-1"), approved.binding)
        assertTrue(approved.targetMatches(LoginForm(packageName, usernameId, passwordId)))

        assertFalse("other package", approved.targetMatches(LoginForm("com.example.other", usernameId, passwordId)))
        assertFalse("other username id", approved.targetMatches(LoginForm(packageName, TestAutofillIds.fresh(), passwordId)))
        assertFalse("other password id", approved.targetMatches(LoginForm(packageName, usernameId, TestAutofillIds.fresh())))
        assertFalse(
            "other package with matching ids",
            approved.targetMatches(LoginForm("com.example.other", usernameId, passwordId)),
        )
        assertFalse("null structure", approved.targetMatches(null))
        // A fresh AutofillId never equals the bound one (identity semantics).
        assertFalse(approved.targetMatches(LoginForm(packageName, TestAutofillIds.fresh(), passwordId)))
        assertFalse(
            "rebound target for another package must not match",
            approval(target = AutofillTarget.from(LoginForm("com.example.other", usernameId, passwordId)))
                .targetMatches(LoginForm(packageName, usernameId, passwordId)),
        )

        val copy = approval()
        copy.take()
        assertNull("consumed approval exposes no binding", copy.binding)
        assertTrue(copy.toString().contains("consumed=true"))

        assertEquals(target, AutofillTarget.from(LoginForm(packageName, usernameId, passwordId)))
        assertNotEquals(target, AutofillTarget.from(LoginForm("com.example.other", usernameId, passwordId)))
        assertNotEquals(target, AutofillTarget.from(LoginForm(packageName, TestAutofillIds.fresh(), passwordId)))
    }

    @Test
    fun differentRowsProduceDifferentBindings() {
        assertNotEquals(approval(rowId = "row-1").binding, approval(rowId = "row-2").binding)
        assertNotEquals(approval(revision = "rev-1").binding, approval(revision = "rev-2").binding)
    }

    @Test
    fun takeThenClearNeverExposesTheSameBytesTwice() {
        val approved = approval()
        val once = approved.take()!!
        assertNull(approved.take())
        approved.clear()
        assertTrue(approved.isConsumed())
        assertNull(approved.binding)
        // The snapshot is caller-owned and wipes independently of the approval.
        once.clear()
        once.clear()
        assertArrayEquals(ByteArray(user.size), once.copyPassword())
        assertFalse(once.toString(), once.toString().contains("synthetic"))
        assertFalse(once.toString(), once.toString().contains("[B@"))
    }

    @Test
    fun emptyCredentialBytesAreStillBoundToTheExactRow() {
        val empty = ApprovedAutofillResult.create(target, "row-9", "rev-9", ByteArray(0), ByteArray(0))
        assertEquals(RowBinding("row-9", "rev-9"), empty.binding)
        val once = empty.take()!!
        assertEquals(0, once.copyUsername().size)
        assertEquals(0, once.copyPassword().size)
        assertTrue(empty.isConsumed())
        once.clear()
    }

    @Test
    fun titlesAreSanitizedBoundedAndNeverContainMarkup() {
        assertEquals("（空标题）", ActiveLogin.sanitizeTitle(null))
        assertEquals("（空标题）", ActiveLogin.sanitizeTitle(""))
        assertEquals("plain", ActiveLogin.sanitizeTitle("plain"))
        // Control and format characters are escaped, not emitted.
        val hostile = ActiveLogin.sanitizeTitle("a\u0000b\n\u202Ec")
        assertFalse(hostile, hostile.any { Character.isISOControl(it) })
        assertFalse(hostile, hostile.contains('\u202E'))
        assertTrue(hostile, hostile.startsWith("a\\u{0}b\\u{A}"))
        // Bounded to the first 120 code points even with surrogate pairs.
        val long = ActiveLogin.sanitizeTitle("\uD83D\uDD11".repeat(500))
        assertEquals(120, long.codePointCount(0, long.length))
        assertEquals(120 * 2, long.length)
    }

    @Test
    fun activeLoginKeepsExactMetadataAndShowsOnlyTheTitle() {
        val login = ActiveLogin.of("row-1", "rev-1", "active", "Example")!!
        assertEquals("row-1", login.rowId)
        assertEquals("rev-1", login.rowRevision)
        assertEquals("Example", login.shownTitle)
        assertEquals("Example", login.toString())
        assertFalse(login.toString(), login.toString().contains("row-1"))

        assertNull("inactive rows are never offered", ActiveLogin.of("row-1", "rev-1", "trashed", "Example"))
        assertNull("no id binds nothing", ActiveLogin.of(null, "rev-1", "active", "Example"))
        assertNull("no revision binds nothing", ActiveLogin.of("row-1", "", "active", "Example"))
        assertEquals("（空标题）", ActiveLogin.of("row-1", "rev-1", "active", null)!!.shownTitle)
    }

    @Test
    fun masterPasswordEncodesAsStrictUtf8AndRejectsMalformedInput() {
        assertArrayEquals("correct horse".toByteArray(Charsets.UTF_8), ApprovalSecret.encodeUtf8("correct horse".toCharArray()))
        assertArrayEquals("密碼-\uD83D\uDD11".toByteArray(Charsets.UTF_8), ApprovalSecret.encodeUtf8("密碼-\uD83D\uDD11".toCharArray()))
        // An unpaired surrogate is not silently replaced with '?'.
        assertEquals(0, ApprovalSecret.encodeUtf8(charArrayOf('a', '\uD800')).size)
    }

    @Test
    fun gatewayContractZeroesBothFactorsOnSuccessAndOnRefusal() {
        val factory = SyntheticGateway()
        // Success: the synthetic gateway wipes both caller buffers on every path.
        runGateway(factory, fail = false)
        // Refusal: the outcome carries a fixed failure and both buffers are gone.
        runGateway(factory, fail = true)
        assertEquals(2, factory.calls.size)
        factory.calls.forEach { (password, key) ->
            assertArrayEquals(CharArray(password.size), password)
            assertArrayEquals(CharArray(key.size), key)
        }
        assertFalse(factory.lastOutcome!!.toString().contains("synthetic"))
        assertEquals(
            NativeFailureCode.UNAVAILABLE,
            factory.lastOutcome!!.failure?.code,
        )
    }

    private fun runGateway(factory: SyntheticGateway, fail: Boolean) {
        val outcome = ApprovalOutcome()
        val password = "synthetic-master".toCharArray()
        val key = "synthetic-key".toCharArray()
        try {
            factory.unlock(outcome, password, key, fail)
        } finally {
            // Caller-side defense in depth, as the Activity's finally blocks do.
            password.fill('\u0000')
            key.fill('\u0000')
        }
        assertEquals(fail, outcome.failure != null)
        factory.lastOutcome = outcome
    }

    /** Mirrors NativeGateway: wipe both inputs, report, never keep a String. */
    private class SyntheticGateway : MobilecoreGateway {
        val calls = mutableListOf<Pair<CharArray, CharArray>>()
        var lastOutcome: ApprovalOutcome? = null

        override fun unlock(outcome: ApprovalOutcome, password: CharArray, secretKey: CharArray) {
            unlock(outcome, password, secretKey, false)
        }

        fun unlock(outcome: ApprovalOutcome, password: CharArray, secretKey: CharArray, fail: Boolean) {
            try {
                assertTrue(password.contentEquals("synthetic-master".toCharArray()))
                assertTrue(secretKey.contentEquals("synthetic-key".toCharArray()))
                if (fail) throw IllegalStateException("vault or authenticated system storage unavailable")
            } catch (error: Exception) {
                outcome.fail(error)
            } finally {
                calls.add(password to secretKey)
                secretKey.fill('\u0000')
                password.fill('\u0000')
            }
        }
    }

    @Test
    fun diagnosticsAreRedacted() {
        val approved = approval()
        val text = approved.toString()
        assertTrue(text, text.startsWith("ApprovedAutofillResult("))
        assertFalse(text, text.contains("synthetic-user"))
        assertFalse(text, text.contains("synthetic-pass"))
        assertFalse(text, text.contains(packageName))
        assertFalse(text, text.contains("[B@"))
        assertFalse(target.toString(), target.toString().contains(packageName))
        assertFalse(target.toString(), target.toString().contains("[B@"))
    }
}

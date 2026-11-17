package org.locklark.android.autofill

import android.service.autofill.FillResponse
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic values only; these are not real credentials. */
class AutofillResultConstructionTest {
    private val packageName = "com.example.nativeapp"
    private val usernameId = TestAutofillIds.fresh()
    private val passwordId = TestAutofillIds.fresh()
    private val target = AutofillTarget.from(LoginForm(packageName, usernameId, passwordId))

    @Test
    fun fieldBuilderIsUsedOnlyFromApi33() {
        assertFalse(AutofillDatasetLevel.usesField(30))
        assertFalse(AutofillDatasetLevel.usesField(32))
        assertTrue(AutofillDatasetLevel.usesField(33))
        assertTrue(AutofillDatasetLevel.usesField(36))
    }

    @Test
    fun valuesBindToExactlyTheTargetUsernameThenPasswordIds() {
        val values = TargetAutofillValues.forTarget(target, "synthetic-user", "synthetic-pass")
        assertEquals(2, values.fieldCount)
        assertSame(usernameId, values.fieldId(0))
        assertSame(passwordId, values.fieldId(1))
        assertEquals("synthetic-user", values.fieldValue(0).textValue)
        assertEquals("synthetic-pass", values.fieldValue(1).textValue)
        assertTrue(values.boundTo(target))

        val other = AutofillTarget.from(LoginForm(packageName, TestAutofillIds.fresh(), passwordId))
        assertFalse("another username id must never bind", values.boundTo(other))
        val swapped = AutofillTarget.from(LoginForm(packageName, passwordId, usernameId))
        assertFalse("swapped ids must never bind", values.boundTo(swapped))
        assertFalse(values.toString(), values.toString().contains("synthetic"))
    }

    /** Text value reused for one field; the count check refuses it first. */
    private val Single: android.view.autofill.AutofillValue = android.view.autofill.AutofillValue.forText("synthetic-user")

    /** A non-text value: the production builder never fills it. */
    private class NonTextValue : android.view.autofill.AutofillValue(null)

    private val EmptyValue: android.view.autofill.AutofillValue = NonTextValue()

    @Test
    fun aTextlessFieldNeverBinds() {
        // Non-text values are refused by production's Dataset guard boundTo().
        val values = object : AutofillFieldValues {
            override val fieldCount get() = 2
            override fun fieldId(index: Int): android.view.autofill.AutofillId = if (index == 0) usernameId else passwordId
            override fun fieldValue(index: Int) = EmptyValue
        }
        assertFalse("a non-text value never fills", values.boundTo(target))
    }

    @Test
    fun aValueSourceWithAnotherIdOrCountNeverBinds() {
        val source = object : AutofillFieldValues {
            override val fieldCount get() = 1
            override fun fieldId(index: Int): android.view.autofill.AutofillId = usernameId
            override fun fieldValue(index: Int) = Single
        }
        assertFalse("one field never binds two ids", source.boundTo(target))
    }

    @Test
    fun onlyAQualifiedNonBrowserPackageCanBeFilled() {
        assertTrue(AutofillFillResult.isFillablePackage("com.example.nativeapp"))
        assertTrue(AutofillFillResult.isFillablePackage("org.locklark.android.test"))
        assertTrue(AutofillFillResult.isFillable(target))
        for (refused in listOf("", "nativeapp", "com..app", "com.example.", ".example.app", "com.android.chrome", "org.mozilla.firefox")) {
            assertFalse("browser/opaque target refilled: $refused", AutofillFillResult.isFillablePackage(refused))
        }
    }

    @Test
    fun canceledResultIsNonNullEmptyAndNeverSuccess() {
        val canceled = AutofillAuthenticationResult.canceled()
        assertEquals(0, canceled.resultCode)
        assertFalse(canceled.isSuccess)
        assertNull(canceled.authenticationResponse)
        val data = canceled.copyData()
        assertNotNull("Android 12+ requires non-null extras", data)
        assertTrue("cancellation carries no fill data", data.isEmpty())
        assertFalse(canceled.toString().contains("synthetic"))
    }

    @Test
    fun successCarriesTheResponseOnlyInTheAuthenticationExtra() {
        // This test covers the result shape only; it does not inspect or claim
        // that the stand-in response contains any Dataset.
        val response = FillResponse()
        val success = AutofillAuthenticationResult.success(response)
        assertEquals(-1, success.resultCode)
        assertTrue(success.isSuccess)
        assertSame(response, success.authenticationResponse)
        val data = success.copyData()
        assertNotNull(data)
        assertFalse(data.isEmpty())
        // The result is a FillResponse, never a Dataset.
        assertSame(response, data.getParcelable<FillResponse>("android.view.autofill.extra.AUTHENTICATION_RESULT"))
        // Each copy is independent; the result itself stays immutable.
        val second = success.copyData()
        assertSame(response, second.getParcelable<FillResponse>("android.view.autofill.extra.AUTHENTICATION_RESULT"))
        assertFalse(success.toString().contains("synthetic"))
    }

    @Test
    fun credentialCopiesAreStrictUtf8AndNeverPrintable() {
        val approved = ApprovedAutofillResult.create(
            target,
            "row-1",
            "rev-1",
            "synthetic-user".toByteArray(),
            "synthetic-pass".toByteArray(),
        )
        val taken = approved.take()!!
        try {
            assertArrayEquals("synthetic-user".toCharArray(), taken.takeUsername())
            assertArrayEquals("synthetic-pass".toCharArray(), taken.takePassword())
        } finally {
            taken.clear()
        }
        assertTrue(approved.isConsumed())
        assertFalse(taken.toString().contains("synthetic"))
    }

    @Test
    fun malformedCredentialBytesNeverDecodeToReplacementText() {
        val approved = ApprovedAutofillResult.create(
            target,
            "row-1",
            "rev-1",
            byteArrayOf(0xC3.toByte(), 0x28), // invalid UTF-8 sequence
            "synthetic-pass".toByteArray(),
        )
        val taken = approved.take()!!
        try {
            assertEquals(0, taken.takeUsername().size)
        } finally {
            taken.clear()
        }
    }
}

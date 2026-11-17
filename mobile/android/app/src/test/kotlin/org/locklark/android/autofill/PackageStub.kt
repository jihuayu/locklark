package org.locklark.android.autofill

import android.view.autofill.AutofillId

/**
 * JVM-only autofill-id factory. AutofillId has package-private constructors on
 * the platform, so unit tests obtain ids only through this helper.
 */
internal object TestAutofillIds {
    private var next = 0

    /** A new, distinct id; never equal to any other id. */
    fun fresh(): AutofillId = AutofillId(next++)
}

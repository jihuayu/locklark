package org.locklark.android.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillPresentationLevelTest {
    @Test
    fun api30Through32UseRemoteViewsAuthenticationPresentation() {
        for (api in 30..32) {
            assertFalse("API $api must use the RemoteViews auth overload", AutofillPresentationLevel.usesPresentations(api))
        }
    }

    @Test
    fun api33AndLaterUsePresentationsMenu() {
        assertTrue(AutofillPresentationLevel.usesPresentations(33))
        assertTrue(AutofillPresentationLevel.usesPresentations(36))
    }
}

package org.locklark.android.autofill

/** API 33 added Presentations; API 30-32 use the RemoteViews auth overload. */
internal object AutofillPresentationLevel {
    const val PRESENTATIONS_API = 33

    fun usesPresentations(apiLevel: Int): Boolean = apiLevel >= PRESENTATIONS_API
}

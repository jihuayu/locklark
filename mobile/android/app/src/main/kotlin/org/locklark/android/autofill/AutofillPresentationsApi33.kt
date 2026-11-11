package org.locklark.android.autofill

import android.annotation.TargetApi
import android.content.IntentSender
import android.service.autofill.FillResponse
import android.service.autofill.Presentations
import android.view.autofill.AutofillId
import android.widget.RemoteViews

/**
 * Isolated so the API 30-32 runtime never loads the API 33 Presentations class.
 */
@TargetApi(AutofillPresentationLevel.PRESENTATIONS_API)
internal object AutofillPresentationsApi33 {
    fun setAuthentication(
        builder: FillResponse.Builder,
        ids: Array<AutofillId>,
        authentication: IntentSender,
        remoteViews: RemoteViews,
    ) {
        val presentations = Presentations.Builder()
            .setMenuPresentation(remoteViews)
            .build()
        builder.setAuthentication(ids, authentication, presentations)
    }
}

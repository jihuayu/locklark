package org.locklark.android.autofill

import android.annotation.TargetApi
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.service.autofill.Presentations
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

/**
 * Isolated so the API 30-32 runtime never loads the API 33 [Field] or
 * [Presentations] types. The platform associates the Field with `id` inside
 * `Dataset.Builder.setField(id, Field)`; the menu presentation lives on the
 * Field so the dataset can be selected in the Autofill UI. API 30-32 keep the
 * supported legacy value/presentation overloads in the caller.
 */
@TargetApi(AutofillDatasetLevel.FIELD_API)
internal object AutofillDatasetApi33 {
    fun addField(
        builder: Dataset.Builder,
        id: AutofillId,
        value: AutofillValue,
        menu: RemoteViews,
    ): Dataset.Builder {
        val presentations = Presentations.Builder().setMenuPresentation(menu).build()
        val field = Field.Builder().setValue(value).setPresentations(presentations).build()
        return builder.setField(id, field)
    }
}

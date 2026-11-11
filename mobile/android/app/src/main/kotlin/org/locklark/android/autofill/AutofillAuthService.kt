package org.locklark.android.autofill

import android.app.PendingIntent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import org.locklark.android.R

/**
 * Authentication-handoff-only AutofillService. It never produces a Dataset,
 * saved value or vault value. Unsupported/ambiguous structures get an explicit
 * empty success; every other path ends in a response or failure callback.
 */
class AutofillAuthService : AutofillService() {
    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        var handoff: AutofillHandoff.Handoff? = null
        val response: FillResponse?
        try {
            if (cancellationSignal.isCanceled) {
                callback.onSuccess(null)
                return
            }
            // Only the newest OS structure participates; older contexts are ignored.
            val latest = request.fillContexts.lastOrNull()
            val form = LoginFormParser.parse(latest?.structure)
            if (form == null) {
                callback.onSuccess(null)
                return
            }
            handoff = AutofillHandoff.create(form)
            response = buildResponse(form, handoff)
            if (cancellationSignal.isCanceled) {
                AutofillHandoff.discard(handoff.token)
                callback.onSuccess(null)
                return
            }
        } catch (_: Exception) {
            handoff?.let { AutofillHandoff.discard(it.token) }
            try {
                callback.onFailure(null)
            } catch (_: Exception) {
                // The framework owns the callback lifetime.
            }
            return
        }
        try {
            callback.onSuccess(response)
        } catch (_: Exception) {
            // The framework owns the callback lifetime.
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // This checkpoint has no save support and must not inspect save data.
        try {
            callback.onFailure(null)
        } catch (_: Exception) {
            // The framework owns the callback lifetime.
        }
    }

    private fun buildResponse(form: LoginForm, handoff: AutofillHandoff.Handoff): FillResponse {
        val remoteViews = RemoteViews(packageName, R.layout.autofill_auth_presentation)
        val pendingIntent = authenticationIntent(handoff)
        val ids: Array<AutofillId> = form.ids
        val builder = FillResponse.Builder()
        if (Build.VERSION.SDK_INT >= AutofillPresentationLevel.PRESENTATIONS_API) {
            // Isolated class: API 30-32 never loads Presentations.
            AutofillPresentationsApi33.setAuthentication(
                builder,
                ids,
                pendingIntent.intentSender,
                remoteViews,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setAuthentication(ids, pendingIntent.intentSender, remoteViews)
        }
        builder.setClientState(AutofillHandoff.clientState(handoff.clientNonce))
        return builder.build()
    }

    private fun authenticationIntent(handoff: AutofillHandoff.Handoff): PendingIntent {
        // Autofill needs to fill in the OS-attached authentication arguments, so
        // the sender is mutable; it is explicit, app-private component-only and
        // single-shot. The token and client-state nonce are validated separately.
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_ONE_SHOT or
            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
        return PendingIntent.getActivity(this, handoff.requestCode, handoff.intent(this), flags)
    }
}

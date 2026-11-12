package org.locklark.android.autofill

import android.app.PendingIntent
import android.content.Context
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import org.locklark.android.security.NativeCallFailure
import org.locklark.android.security.NativeFailureCode
import org.locklark.android.security.NativePhase

/**
 * Authentication-handoff AutofillService. Its FillResponse only ever contains
 * one authentication challenge: it never produces a Dataset, saved value or
 * vault value. The challenge is remembered fully built in [AutofillServiceState]
 * together with the client-state key the OS hands back, so an approved
 * Activity can rebuild the authentication result for exactly this request.
 * Unsupported/ambiguous structures get an explicit empty success; every other
 * path ends in a response or failure callback.
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
            response = AutofillServiceState.buildChallenge(this, packageName, form, handoff)
            if (cancellationSignal.isCanceled) {
                AutofillHandoff.discard(handoff.token)
                AutofillServiceState.forget(handoff.clientNonce)
                // No response, so no challenge and no fill for this request.
                callback.onSuccess(null)
                return
            }
            try {
                callback.onSuccess(response)
            } catch (_: Exception) {
                // The framework owns the callback lifetime.
            }
        } catch (_: Exception) {
            // No FillResponse is delivered here: retire both the created
            // handoff record and any reviewed response for its nonce.
            handoff?.let {
                AutofillHandoff.discard(it.token)
                AutofillServiceState.forget(it.clientNonce)
            }
            try {
                callback.onFailure(null)
            } catch (_: Exception) {
                // The framework owns the callback lifetime.
            }
            return
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
}

/**
 * Service-side state shared by [AutofillAuthService] and the explicit approval
 * Activity: platform service creation, the short-lived reviewed response
 * cache and the pending-intent factory. Process-local; restart drops it.
 */
internal interface AutofillServicePort {
    fun presentation(packageName: String): AutofillPresentationFactory

    fun newPendingIntent(
        context: Context,
        requestCode: Int,
        intent: android.content.Intent,
    ): android.app.PendingIntent
}

internal object AutofillPendingIntentFlags {
    /**
     * FLAG_MUTABLE exists only from API 31, so API 30 must never receive it.
     */
    const val MUTABLE_API = Build.VERSION_CODES.S

    /**
     * Autofill fills the OS-attached authentication arguments into this
     * explicit, app-private, single-shot sender, so it must be one-shot AND
     * mutable from API 31 where mutability became explicit.
     */
    const val BASE = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_ONE_SHOT
    const val MUTABLE = PendingIntent.FLAG_MUTABLE

    fun flags(api: Int): Int = BASE or (if (api >= MUTABLE_API) MUTABLE else 0)
}

internal object NativeAutofillServicePort : AutofillServicePort {
    override fun presentation(packageName: String): AutofillPresentationFactory =
        NativeAutofillPresentationFactory(packageName)

    override fun newPendingIntent(
        context: Context,
        requestCode: Int,
        intent: android.content.Intent,
    ) = PendingIntent.getActivity(
        context,
        requestCode,
        intent,
        // The handoff token and client-state nonce are validated separately.
        AutofillPendingIntentFlags.flags(Build.VERSION.SDK_INT),
    )
}

/**
 * Process-local reviewed-authentication responses. A response is keyed by the
 * exact client-state value the OS hands back from the approved Activity, kept
 * for at most [REVIEWED_TTL_MS], capped in count and total size, replaced on a
 * duplicate key and taken exactly once. It never stores a credential; the
 * cached response is the challenge-only FillResponse.
 */
internal object AutofillServiceState {
    const val MAX_REVIEWED = 8
    const val REVIEWED_TTL_MS = 5 * 60_000L
    const val REVIEWED_CAPACITY = 32 * 1024

    private class Entry(val response: FillResponse, val size: Int, val createdAt: Long)

    private val reviewed = LinkedHashMap<String, Entry>()
    private var reviewedBytes = 0

    fun presentation(packageName: String): AutofillPresentationFactory =
        NativeAutofillServicePort.presentation(packageName)

    fun context(
        context: Context,
        packageName: String,
        presentation: AutofillPresentationFactory = presentation(packageName),
        port: AutofillServicePort = NativeAutofillServicePort,
    ) = AutofillChallengeContext(packageName, presentation) { requestCode, intent ->
        port.newPendingIntent(context, requestCode, intent)
    }

    /**
     * Builds and remembers the one challenge response of [form]. A response
     * that cannot be parceled under [REVIEWED_CAPACITY] is never cached and is
     * never returned: the handoff is retired and the call fails closed.
     */
    fun buildChallenge(
        context: Context,
        packageName: String,
        form: LoginForm,
        handoff: AutofillHandoff.Handoff,
        presentation: AutofillPresentationFactory = presentation(packageName),
    ): FillResponse {
        val challenge = context(context, packageName, presentation).challenge(handoff, form)
        val response = AutofillChallengeResponse.build(form, challenge, presentation)
        val size = measuredSize(response)
        if (size == null) {
            // Unmeasurable under the bounded cache: the Activity must never
            // find this response, so this FillRequest fails closed.
            AutofillHandoff.discard(null, handoff.clientNonce, form)
            throw NativeCallFailure(NativePhase.OPERATION, NativeFailureCode.INVALID)
        }
        remember(handoff.clientNonce, response, measure = { size })
        return response
    }

    /**
     * Remembers [response] unless it cannot be measured. An unmeasured parcel
     * is never assumed to be zero bytes under [REVIEWED_CAPACITY]: it is not
     * cached, so the Activity finds no reviewed response and fails closed.
     */
    fun remember(
        key: String,
        response: FillResponse,
        now: Long = android.os.SystemClock.elapsedRealtime(),
        measure: (FillResponse) -> Int? = ::measuredSize,
    ) {
        val size = measure(response) ?: return
        synchronized(reviewed) {
            pruneLocked(now)
            reviewed.remove(key)?.let { reviewedBytes -= it.size }
            if (size > REVIEWED_CAPACITY) {
                // Uncacheable: the Activity will find no reviewed response and
                // fails closed without ever offering a fill.
                return
            }
            while (reviewed.size >= MAX_REVIEWED && reviewed.isNotEmpty()) {
                reviewedBytes -= reviewed.remove(reviewed.keys.first())!!.size
            }
            reviewed[key] = Entry(response, size, now)
            reviewedBytes += size
        }
    }

    /** The reviewed response for [key], without consuming it. */
    fun peek(key: String, now: Long = android.os.SystemClock.elapsedRealtime()): FillResponse? = synchronized(reviewed) {
        pruneLocked(now)
        reviewed[key]?.response
    }

    /** One-use: removes [key] before returning, whatever the outcome. */
    fun take(key: String, now: Long = android.os.SystemClock.elapsedRealtime()): FillResponse? = synchronized(reviewed) {
        pruneLocked(now)
        reviewed.remove(key)?.also { reviewedBytes -= it.size }?.response
    }

    /** Removes one reviewed response (e.g. the request was cancelled). */
    fun forget(key: String) = synchronized(reviewed) {
        reviewed.remove(key)?.let { reviewedBytes -= it.size }
    }

    fun clear() = synchronized(reviewed) {
        reviewed.clear()
        reviewedBytes = 0
    }

    fun count(): Int = synchronized(reviewed) { reviewed.size }

    private fun pruneLocked(now: Long) {
        val iterator = reviewed.values.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.createdAt > REVIEWED_TTL_MS) {
                reviewedBytes -= entry.size
                iterator.remove()
            }
        }
    }

    /** The parceled size, or null when the response cannot be measured. */
    internal fun measuredSize(response: FillResponse): Int? {
        val parcel = android.os.Parcel.obtain()
        return try {
            parcel.writeParcelable(response, 0)
            parcel.dataSize()
        } catch (_: RuntimeException) {
            null
        } finally {
            parcel.recycle()
        }
    }
}

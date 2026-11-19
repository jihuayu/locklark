package org.locklark.android.autofill

import android.app.Activity
import android.app.PendingIntent
import android.os.Build
import android.os.Bundle
import android.os.Parcel
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import org.locklark.android.R
import org.locklark.android.security.NativeCallFailure
import org.locklark.android.security.NativeFailureCode
import org.locklark.android.security.NativePhase

/** Which Dataset field builder the runtime supports. */
internal object AutofillDatasetLevel {
    /** API that added `Dataset.Builder.setField(Field)`; API 30-32 use `setValue`. */
    const val FIELD_API = 33

    fun usesField(api: Int): Boolean = api >= FIELD_API
}

/** Which Dataset field builder API the current runtime supports. */
internal interface AutofillFieldLevel {
    fun usesField(): Boolean
}

internal object BuildAutofillFieldLevel : AutofillFieldLevel {
    override fun usesField(): Boolean = AutofillDatasetLevel.usesField(Build.VERSION.SDK_INT)
}

/**
 * Field-to-value mapping of the one Dataset built from an explicit approval.
 * It is built from the caller's text copies synchronously, so those copies can
 * be wiped before the response leaves the Activity. The only binding it
 * accepts is exactly the target's username then password id. Diagnostics and
 * [toString] never contain the values.
 */
internal interface AutofillFieldValues {
    val fieldCount: Int
    fun fieldId(index: Int): AutofillId
    fun fieldValue(index: Int): AutofillValue

    /**
     * True only when the fields are exactly the username then password of
     * [target], each with a text value. The production response builder
     * refuses to build a Dataset unless this holds.
     */
    fun boundTo(target: AutofillTarget): Boolean {
        if (fieldCount != 2) return false
        if (fieldId(0) !== target.usernameId || fieldId(1) !== target.passwordId) return false
        val user = fieldValue(0)
        val pass = fieldValue(1)
        return user.isText && pass.isText
    }
}

/** The exact AutofillIds of the consumed OS FillRequest. */
internal class TargetAutofillValues private constructor(
    private val usernameId: AutofillId,
    private val passwordId: AutofillId,
    private val username: AutofillValue,
    private val password: AutofillValue,
) : AutofillFieldValues {
    override val fieldCount: Int get() = 2
    override fun fieldId(index: Int): AutofillId = if (index == 0) usernameId else passwordId
    override fun fieldValue(index: Int): AutofillValue = if (index == 0) username else password

    override fun boundTo(target: AutofillTarget): Boolean =
        usernameId === target.usernameId && passwordId === target.passwordId && super.boundTo(target)

    override fun toString(): String = "[autofill target values]"

    companion object {
        fun forTarget(target: AutofillTarget, username: String, password: String): TargetAutofillValues =
            TargetAutofillValues(
                target.usernameId,
                target.passwordId,
                AutofillValue.forText(username),
                AutofillValue.forText(password),
            )
    }
}

/**
 * Static, non-secret presentations: the same fixed text for every user, login,
 * challenge and result. No credential reaches a title, content description or
 * any other presentation.
 */
internal interface AutofillPresentationFactory {
    /** The challenge menu item. */
    fun menu(): RemoteViews

    /**
     * The static, non-secret Dataset presentation. API 33+ wraps it in a
     * [Presentations] menu item inside the isolated [AutofillDatasetApi33]
     * class; API 30-32 use it as the legacy per-field Dataset presentation.
     */
    fun dataset(): RemoteViews
}

internal class NativeAutofillPresentationFactory(private val packageName: String) : AutofillPresentationFactory {
    override fun menu(): RemoteViews = RemoteViews(packageName, R.layout.autofill_auth_presentation)

    override fun dataset(): RemoteViews = RemoteViews(packageName, R.layout.autofill_dataset_presentation)
}

/**
 * The one terminal authentication result of an explicit approval: exactly one
 * of the two static extras shapes Android requires for an Activity opened as an
 * Autofill authentication response:
 * - success: `RESULT_OK` + non-null [AutofillManager.EXTRA_AUTHENTICATION_RESULT]
 *   [FillResponse] (never a Dataset);
 * - cancellation on Android 12+: `RESULT_CANCELED` + non-null empty Bundle.
 */
internal class AutofillAuthenticationResult private constructor(
    val resultCode: Int,
    private val data: Bundle?,
    private val response: FillResponse?,
) {
    val isSuccess: Boolean get() = resultCode == Activity.RESULT_OK

    /** The result FillResponse; never a Dataset (Android rejects that). */
    val authenticationResponse: FillResponse? get() = response

    /** The exact extras Android receives; a fresh copy on every call. */
    fun copyData(): Bundle = data?.let { Bundle(it) } ?: Bundle()

    override fun toString(): String = "[autofill authentication result ${if (isSuccess) "ok" else "canceled"}]"

    companion object {
        /** Non-null empty result for every cancel, back, onStop and failure path. */
        fun canceled(): AutofillAuthenticationResult = AutofillAuthenticationResult(Activity.RESULT_CANCELED, null, null)

        fun success(response: FillResponse): AutofillAuthenticationResult =
            AutofillAuthenticationResult(
                Activity.RESULT_OK,
                Bundle().apply { putParcelable(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response) },
                response,
            )
    }
}

/**
 * The authentication challenge of exactly one FillRequest, carried unchanged in
 * the service client state so the approval Activity can bind to the exact
 * request. It carries no credential: only the target package/ids, the one-use
 * handoff nonce and the one-shot explicit authentication intent sender.
 */
internal class AutofillChallenge(
    val form: LoginForm,
    val clientNonce: String,
    val requestCode: Int,
    val authentication: PendingIntent,
) {
    fun toBundle(): Bundle = Bundle().apply {
        putParcelable(EXTRA_FORM, form)
        putString(EXTRA_CLIENT_NONCE, clientNonce)
        putInt(EXTRA_REQUEST_CODE, requestCode)
        putParcelable(EXTRA_AUTHENTICATION, authentication)
    }

    override fun toString(): String = "[autofill challenge]"

    companion object {
        private const val EXTRA_FORM = "org.locklark.android.autofill.challenge.FORM"
        private const val EXTRA_CLIENT_NONCE = AutofillHandoff.EXTRA_CLIENT_NONCE
        private const val EXTRA_REQUEST_CODE = "org.locklark.android.autofill.challenge.REQUEST_CODE"
        private const val EXTRA_AUTHENTICATION = "org.locklark.android.autofill.challenge.AUTHENTICATION"

        /**
         * Rebuilds a challenge from a client state this build wrote, or null
         * for anything absent, malformed, mismatched or out of scope.
         */
        fun fromBundle(bundle: Bundle?): AutofillChallenge? {
            bundle ?: return null
            return try {
                @Suppress("DEPRECATION")
                val form = bundle.getParcelable(EXTRA_FORM) as? LoginForm ?: return null
                if (!AutofillFillResult.isFillablePackage(form.packageName)) return null
                val nonce = bundle.getString(EXTRA_CLIENT_NONCE)?.takeIf { it.isNotEmpty() } ?: return null
                val requestCode = bundle.getInt(EXTRA_REQUEST_CODE, 0)
                if (requestCode <= 0) return null
                @Suppress("DEPRECATION")
                val authentication = bundle.getParcelable(EXTRA_AUTHENTICATION) as? PendingIntent ?: return null
                if (!roundTrips(authentication)) return null
                AutofillChallenge(form, nonce, requestCode, authentication)
            } catch (_: RuntimeException) {
                null
            }
        }

        private fun roundTrips(pendingIntent: PendingIntent): Boolean {
            val parcel = Parcel.obtain()
            return try {
                parcel.writeParcelable(pendingIntent, 0)
                parcel.setDataPosition(0)
                parcel.readParcelable<PendingIntent>(AutofillChallenge::class.java.classLoader) != null
            } catch (_: RuntimeException) {
                false
            } finally {
                parcel.recycle()
            }
        }
    }
}

/** The service's inputs for building a challenge; tests supply synthetic ones. */
internal class AutofillChallengeContext(
    val packageName: String,
    val presentation: AutofillPresentationFactory,
    private val newPendingIntent: (requestCode: Int, intent: android.content.Intent) -> PendingIntent,
) {
    fun challenge(handoff: AutofillHandoff.Handoff, form: LoginForm): AutofillChallenge {
        val sender = newPendingIntent(handoff.requestCode, handoff.intent(packageName))
        return AutofillChallenge(form, handoff.clientNonce, handoff.requestCode, sender)
    }
}

/**
 * The FillResponse shown before any approval: one challenge bound to exactly
 * the two target ids, no Dataset and no value. API 33+ uses Presentations;
 * API 30-32 use the RemoteViews authentication overload.
 */
internal object AutofillChallengeResponse {
    fun build(form: LoginForm, challenge: AutofillChallenge, presentation: AutofillPresentationFactory): FillResponse {
        val ids: Array<AutofillId> = form.ids
        val menu = presentation.menu()
        val builder = FillResponse.Builder()
        if (AutofillPresentationLevel.usesPresentations(Build.VERSION.SDK_INT)) {
            // Isolated class: API 30-32 never load Presentations.
            AutofillPresentationsApi33.setAuthentication(builder, ids, challenge.authentication.intentSender, menu)
        } else {
            @Suppress("DEPRECATION")
            builder.setAuthentication(ids, challenge.authentication.intentSender, menu)
        }
        builder.setClientState(challenge.toBundle())
        return builder.build()
    }
}

/**
 * The only place approval values become a platform response. Both inputs are
 * caller-owned text copies: they are wiped on every path, and both
 * [AutofillValue]s plus the complete FillResponse with exactly one Dataset are
 * built synchronously, in that order, so the caller can wipe every other copy
 * immediately afterwards.
 */
internal object AutofillFillResult {
    /**
     * Only a fully qualified native application package can ever be filled.
     * Browser packages (not a package name, and refused by the parser anyway)
     * stay fail-closed beyond the package + id binding.
     */
    fun isFillable(target: AutofillTarget): Boolean = isFillablePackage(target.packageName)

    fun isFillablePackage(packageName: String): Boolean =
        FILLABLE_PACKAGE.matches(packageName) && !LoginFormParser.isBrowserPackage(packageName)

    fun build(
        target: AutofillTarget,
        username: CharArray?,
        password: CharArray?,
        level: AutofillFieldLevel = BuildAutofillFieldLevel,
        presentation: AutofillPresentationFactory,
    ): FillResponse {
        try {
            // Browser targets stay fail-closed: only native package ids fill.
            if (!isFillable(target)) invalid()
            if (username == null || password == null || username.isEmpty() || password.isEmpty()) invalid()
            val values = TargetAutofillValues.forTarget(target, String(username), String(password))
            // Exactly the target's username then password id: neither alone binds.
            if (!values.boundTo(target)) invalid()
            val usesField = level.usesField()
            val datasetPresentation = presentation.dataset()
            val builder = Dataset.Builder()
            // Password first, username last: the username id stays the
            // dataset's primary value, which is also the focused target field.
            for (index in 1 downTo 0) {
                val id = if (index == 0) target.usernameId else target.passwordId
                if (values.fieldId(index) !== id) invalid()
                val value = values.fieldValue(index)
                if (usesField) {
                    // Isolated class: API 30-32 never load the API 33 types.
                    AutofillDatasetApi33.addField(builder, id, value, datasetPresentation)
                } else {
                    @Suppress("DEPRECATION")
                    builder.setValue(id, value, datasetPresentation)
                }
            }
            return FillResponse.Builder().addDataset(builder.build()).build()
        } catch (error: Exception) {
            throw error as? NativeCallFailure ?: NativeCallFailure(NativePhase.OPERATION, NativeFailureCode.UNKNOWN)
        } finally {
            username?.fill('\u0000')
            password?.fill('\u0000')
        }
    }

    private val FILLABLE_PACKAGE = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

    private fun invalid(): Nothing = throw NativeCallFailure(NativePhase.OPERATION, NativeFailureCode.INVALID)
}

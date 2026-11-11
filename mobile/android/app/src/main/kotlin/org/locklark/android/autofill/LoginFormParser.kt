package org.locklark.android.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/**
 * The only shape this checkpoint accepts from the OS: one enabled, visible
 * username field followed by one enabled, visible password field. Field
 * contents, saved values and vault data are never read.
 */
internal data class LoginForm(
    val packageName: String,
    val usernameId: AutofillId,
    val passwordId: AutofillId,
) {
    val ids: Array<AutofillId> get() = arrayOf(usernameId, passwordId)
}

internal object LoginFormParser {
    private val CARD_HINTS = setOf(
        View.AUTOFILL_HINT_CREDIT_CARD_NUMBER,
        View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_DATE,
        View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_DAY,
        View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_MONTH,
        View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_YEAR,
        View.AUTOFILL_HINT_CREDIT_CARD_SECURITY_CODE,
    )
    // The platform appends its hidden heuristic marker "passwordAuto" to
    // password-variation fields, alongside any declared password hint.
    private val PASSWORD_HINTS = setOf(View.AUTOFILL_HINT_PASSWORD, PASSWORD_AUTO_HINT)
    private val USERNAME_HINTS = setOf(
        View.AUTOFILL_HINT_USERNAME,
        View.AUTOFILL_HINT_EMAIL_ADDRESS,
    )
    private val FORBIDDEN_HINTS = setOf(
        "smsotp", "2faappotp", "otp", "one-time-code", "onetimecode",
        "verificationcode", "newpassword", "newusername",
    )

    private class Field(val id: AutofillId, val password: Boolean)

    fun parse(structure: AssistStructure?): LoginForm? {
        if (structure == null) return null
        val component = structure.activityComponent ?: return null
        val packageName = component.packageName
        if (packageName.isNullOrBlank()) return null
        if (structure.windowNodeCount != 1) return null
        val window = structure.getWindowNodeAt(0) ?: return null
        val root = window.rootViewNode ?: return null
        val fields = mutableListOf<Field>()
        var rejected = false
        val pending = ArrayDeque<Pair<AssistStructure.ViewNode, Int>>()
        pending.addLast(root to 0)
        while (pending.isNotEmpty()) {
            val (node, depth) = pending.removeLast()
            if (depth > MAX_DEPTH) return null
            val rawHints = node.autofillHints
            val hints: List<String> = rawHints?.filter { it.isNotBlank() } ?: emptyList()
            if (hints.any(::forbiddenHint)) rejected = true
            val type = node.autofillType
            if (type == View.AUTOFILL_TYPE_TEXT) {
                val id = node.autofillId ?: return null
                if (!node.isEnabled || node.visibility != View.VISIBLE) return null
                val hintSet = hints.toSet()
                val passwordByType = passwordInput(node.inputType)
                val passwordByHint = hintSet.any { it in PASSWORD_HINTS }
                val usernameByHint = hintSet.any { it in USERNAME_HINTS }
                if (passwordByType || passwordByHint) {
                    if (usernameByHint) return null
                    if (hintSet.any { it !in PASSWORD_HINTS }) return null
                    fields.add(Field(id, true))
                } else {
                    // Username/email must be explicit; an unhinted text field is ambiguous.
                    if (!usernameByHint) return null
                    fields.add(Field(id, false))
                }
            } else if (hints.any { it in PASSWORD_HINTS }) {
                // A password hint on a non-text field is malformed input.
                return null
            }
            for (index in node.childCount - 1 downTo 0) {
                val child = node.getChildAt(index) ?: return null
                pending.addLast(child to depth + 1)
            }
        }
        if (rejected) return null
        if (fields.size != 2) return null
        val username = fields[0]
        val password = fields[1]
        if (username.password || !password.password) return null
        if (username.id == password.id) return null
        return LoginForm(packageName, username.id, password.id)
    }

    private fun passwordInput(inputType: Int): Boolean {
        if (inputType and InputType.TYPE_MASK_CLASS != InputType.TYPE_CLASS_TEXT) return false
        return when (inputType and InputType.TYPE_MASK_VARIATION) {
            InputType.TYPE_TEXT_VARIATION_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD -> true
            else -> false
        }
    }

    private fun forbiddenHint(hint: String): Boolean {
        if (hint in CARD_HINTS) return true
        val normalized = hint.lowercase()
        return normalized in FORBIDDEN_HINTS || "otp" in normalized || "creditcard" in normalized
    }

    private const val PASSWORD_AUTO_HINT = "passwordAuto"
    private const val MAX_DEPTH = 256
}

package org.locklark.android.autofill

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.widget.EditText
import android.widget.LinearLayout

/**
 * Synthetic login target living only in the test APK. It has no network or
 * vault access, and the smoke only checks that a cancelled authentication
 * leaves both fields empty.
 */
class AutofillSmokeTargetActivity : Activity() {
    private lateinit var username: EditText
    private var requested = false

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN)
        val density = resources.displayMetrics.density
        fun dp(value: Int): Int = (value * density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(48), dp(24), dp(24))
        }
        username = EditText(this).apply {
            contentDescription = SMOKE_USERNAME
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_NORMAL
            setSingleLine(true)
        }
        root.addView(
            username,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
        root.addView(
            EditText(this).apply {
                contentDescription = SMOKE_PASSWORD
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
                setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                setSingleLine(true)
            },
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
        setContentView(root)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || requested) return
        requested = true
        username.postDelayed({
            username.requestFocus()
            getSystemService(AutofillManager::class.java)?.requestAutofill(username)
        }, 300)
    }

    companion object {
        const val SMOKE_USERNAME = "autofill-smoke-username"
        const val SMOKE_PASSWORD = "autofill-smoke-password"
    }
}

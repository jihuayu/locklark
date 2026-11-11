package org.locklark.android.autofill

import android.app.Activity
import android.app.assist.AssistStructure
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.locklark.android.R

/**
 * Explicit authentication challenge. It validates the OS-attached structure,
 * package and AutofillIds against the one-use handoff before rendering. It
 * never returns EXTRA_AUTHENTICATION_RESULT and never supplies a Dataset.
 */
class AutofillAuthActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        @Suppress("DEPRECATION")
        val structure = intent?.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        val clientState = intent?.getBundleExtra(AutofillManager.EXTRA_CLIENT_STATE)
        val form = LoginFormParser.parse(structure)
        val valid = AutofillHandoff.consume(
            intent?.getStringExtra(AutofillHandoff.EXTRA_HANDOFF),
            clientState?.getString(AutofillHandoff.EXTRA_CLIENT_NONCE),
            form,
        )
        if (!valid) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        showChallenge()
    }

    private fun showChallenge() {
        val density = resources.displayMetrics.density
        fun dp(value: Int): Int = (value * density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(32), dp(24), dp(24))
        }
        val title = TextView(this).apply {
            id = R.id.autofill_auth_title
            text = getString(R.string.autofill_challenge_title)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            gravity = Gravity.CENTER
        }
        val body = TextView(this).apply {
            id = R.id.autofill_auth_body
            text = getString(R.string.autofill_challenge_body)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            gravity = Gravity.CENTER
            setPadding(0, dp(16), 0, dp(24))
        }
        val cancel = Button(this).apply {
            id = R.id.autofill_auth_cancel
            text = getString(R.string.autofill_challenge_cancel)
            isAllCaps = false
            setOnClickListener { cancelAndClose() }
        }
        root.addView(
            title,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
        root.addView(
            body,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
        root.addView(
            cancel,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
        setContentView(root)
    }

    private fun cancelAndClose() {
        setResult(RESULT_CANCELED)
        finish()
    }

    @Deprecated("Back must close the challenge without a Dataset")
    override fun onBackPressed() {
        setResult(RESULT_CANCELED)
        @Suppress("DEPRECATION")
        super.onBackPressed()
    }
}

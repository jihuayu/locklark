package org.locklark.android.autofill

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.view.autofill.AutofillId
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Process-local, short-lived, single-use records binding an OS FillRequest to
 * the later explicit authentication launch. Restart drops every record.
 * No field value, token or package is ever logged or persisted.
 */
internal object AutofillHandoff {
    const val ACTION_AUTHENTICATE = "org.locklark.android.action.AUTOFILL_AUTHENTICATE"
    const val EXTRA_HANDOFF = "org.locklark.android.extra.AUTOFILL_HANDOFF"
    const val EXTRA_CLIENT_NONCE = "org.locklark.android.extra.AUTOFILL_CLIENT_NONCE"

    private const val TTL_MS = 60_000L
    private const val MAX_RECORDS = 16

    private class Record(
        val token: String,
        val clientNonce: String,
        val packageName: String,
        val usernameId: AutofillId,
        val passwordId: AutofillId,
        val createdAt: Long,
        val requestCode: Int,
    )

    class Handoff internal constructor(
        val token: String,
        val clientNonce: String,
        val requestCode: Int,
    ) {
        override fun toString(): String = "[autofill handoff]"

        fun intent(context: Context): Intent = Intent(context, AutofillAuthActivity::class.java)
            .setAction(ACTION_AUTHENTICATE)
            .putExtra(EXTRA_HANDOFF, token)
    }

    private val records = LinkedHashMap<String, Record>()
    private val random = SecureRandom()

    fun create(form: LoginForm): Handoff = synchronized(records) {
        pruneLocked()
        while (records.size >= MAX_RECORDS) {
            records.remove(records.keys.first())
        }
        val token = randomToken()
        val nonce = randomToken()
        val requestCode = random.nextInt(Int.MAX_VALUE - 1) + 1
        val record = Record(
            token = token,
            clientNonce = nonce,
            packageName = form.packageName,
            usernameId = form.usernameId,
            passwordId = form.passwordId,
            createdAt = SystemClock.elapsedRealtime(),
            requestCode = requestCode,
        )
        records[token] = record
        Handoff(token, nonce, requestCode)
    }

    /**
     * Removes the record before any comparison so a replay can never succeed.
     * The OS-attached package and ids must equal the bound FillRequest values.
     */
    fun consume(token: String?, clientNonce: String?, form: LoginForm?): Boolean {
        if (token == null || clientNonce == null || form == null) return false
        val record = synchronized(records) { records.remove(token) } ?: return false
        if (SystemClock.elapsedRealtime() - record.createdAt > TTL_MS) return false
        if (!constantTimeEquals(record.clientNonce, clientNonce)) return false
        if (record.packageName != form.packageName) return false
        if (!record.usernameId.equals(form.usernameId)) return false
        if (!record.passwordId.equals(form.passwordId)) return false
        return true
    }

    fun discard(token: String) {
        synchronized(records) { records.remove(token) }
    }

    fun clientState(nonce: String): Bundle = Bundle().apply {
        putString(EXTRA_CLIENT_NONCE, nonce)
    }

    private fun pruneLocked() {
        val now = SystemClock.elapsedRealtime()
        val iterator = records.values.iterator()
        while (iterator.hasNext()) {
            if (now - iterator.next().createdAt > TTL_MS) iterator.remove()
        }
    }

    private fun randomToken(): String {
        val bytes = ByteArray(TOKEN_BYTES)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun constantTimeEquals(expected: String, actual: String): Boolean =
        MessageDigest.isEqual(expected.toByteArray(Charsets.UTF_8), actual.toByteArray(Charsets.UTF_8))

    private const val TOKEN_BYTES = 32
}

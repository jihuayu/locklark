package org.locklark.android.autofill

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
 *
 * A record moves from PENDING (created for a FillResponse, never yet claimed)
 * to BOUND (claimed by exactly one Activity intent, which was verified against
 * the OS-attached structure) and then only to retired: consumed at positive
 * approval, or removed on cancel/failure/destroy/discard. A record is never
 * re-claimed, so a configuration-change restart of the Activity cannot bind the
 * handoff again.
 */
internal object AutofillHandoff {
    const val ACTION_AUTHENTICATE = "org.locklark.android.action.AUTOFILL_AUTHENTICATE"
    const val EXTRA_HANDOFF = "org.locklark.android.extra.AUTOFILL_HANDOFF"
    const val EXTRA_CLIENT_NONCE = "org.locklark.android.extra.AUTOFILL_CLIENT_NONCE"

    private const val TTL_MS = 60_000L
    private const val MAX_RECORDS = 16

    private enum class State { PENDING, BOUND }

    private class Record(
        val token: String,
        val clientNonce: String,
        val packageName: String,
        val usernameId: AutofillId,
        val passwordId: AutofillId,
        val createdAt: Long,
        val requestCode: Int,
        var state: State = State.PENDING,
    )

    class Handoff internal constructor(
        val token: String,
        val clientNonce: String,
        val requestCode: Int,
    ) {
        override fun toString(): String = "[autofill handoff]"

        /** Explicit component intent for the app that registered this handoff. */
        fun intent(packageName: String): Intent = Intent(ACTION_AUTHENTICATE)
            .setClassName(packageName, AUTH_ACTIVITY)
            .putExtra(EXTRA_HANDOFF, token)
    }

    private val records = LinkedHashMap<String, Record>()
    private val random = SecureRandom()

    /** Monotonic clock; tests inject a synthetic one. Production is elapsed realtime. */
    internal var clock: () -> Long = { SystemClock.elapsedRealtime() }

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
            createdAt = clock(),
            requestCode = requestCode,
        )
        records[token] = record
        Handoff(token, nonce, requestCode)
    }

    /**
     * Binds a pending record to this authentication launch. The record is
     * removed on every refusal (unknown, expired, replayed, wrong nonce or
     * mismatch with the OS-attached package/ids), so a rejected intent can
     * never be retried. On success the record stays BOUND for this one
     * Activity only, until [consume] or [discard].
     */
    fun claim(token: String?, clientNonce: String?, form: LoginForm?): Boolean {
        if (token == null || clientNonce == null || form == null) return false
        return synchronized(records) {
            val record = records[token]
            if (record == null || record.state != State.PENDING) {
                records.remove(token)
                return@synchronized false
            }
            val now = clock()
            val valid = now - record.createdAt <= TTL_MS &&
                constantTimeEquals(record.clientNonce, clientNonce) &&
                record.packageName == form.packageName &&
                record.usernameId.equals(form.usernameId) &&
                record.passwordId.equals(form.passwordId)
            if (!valid) {
                records.remove(token)
                return@synchronized false
            }
            // The TTL never extends: the record still expires from creation.
            record.state = State.BOUND
            true
        }
    }

    /**
     * Retires the BOUND record named by [token] (or, without a token, by the
     * claimed [clientNonce]) only if it is still unexpired, its exact package
     * and both OS AutofillIds equal [form]'s and, for a supplied [token], the
     * supplied [clientNonce] equals the record's in constant time. Any call
     * removes the record whatever the outcome, so a handoff is consumed at most
     * once and a mismatch (wrong or missing nonce, target, ids or expiry) can
     * never be retried.
     *
     * A supplied (even unknown) [token] names only that exact record and never
     * falls back to the nonce lookup. A missing or malformed [form] retires the
     * named BOUND record by token, so a malformed launch can never leave a
     * named record replayable; without a token a supplied [clientNonce] retires
     * merely the BOUND record it names, while an unknown nonce retires nothing.
     */
    fun consume(token: String?, clientNonce: String?, form: LoginForm?): Boolean = synchronized(records) {
        if (form == null) {
            if (token != null) {
                records[token]?.let { if (it.state == State.BOUND) records.remove(it.token) }
            } else if (clientNonce != null) {
                dropLocked { it.state == State.BOUND && constantTimeEquals(it.clientNonce, clientNonce) }
            }
            return@synchronized false
        }
        val record: Record = (if (token != null) {
            records[token]
        } else if (clientNonce != null) {
            records.values.firstOrNull { it.state == State.BOUND && constantTimeEquals(it.clientNonce, clientNonce) }
        } else {
            null
        }) ?: return@synchronized false
        records.remove(record.token)
        record.state == State.BOUND &&
            clock() - record.createdAt <= TTL_MS &&
            clientNonce != null &&
            constantTimeEquals(record.clientNonce, clientNonce) &&
            record.packageName == form.packageName &&
            record.usernameId.equals(form.usernameId) &&
            record.passwordId.equals(form.passwordId)
    }

    /**
     * Removes a record in any state (cancel, failure, destroy). Without a token,
     * removes the PENDING record this service created for [form] and nonce.
     */
    fun discard(token: String?, clientNonce: String? = null, form: LoginForm? = null) {
        if (token != null) {
            synchronized(records) { records.remove(token) }
            return
        }
        if (clientNonce == null || form == null) return
        synchronized(records) {
            dropLocked {
                it.state == State.PENDING && constantTimeEquals(it.clientNonce, clientNonce) &&
                    it.packageName == form.packageName &&
                    it.usernameId.equals(form.usernameId) && it.passwordId.equals(form.passwordId)
            }
        }
    }

    private fun dropLocked(predicate: (Record) -> Boolean) {
        records.values.firstOrNull(predicate)?.let { records.remove(it.token) }
    }

    /** Test-only: drops every record without touching the injected clock. */
    internal fun clear() = synchronized(records) { records.clear() }

    /** Whether a record with [token] exists in the given lifecycle state (diagnostics/tests). */
    fun state(token: String?): String? = synchronized(records) {
        records[token]?.state?.name
    }

    fun clientState(nonce: String): Bundle = Bundle().apply {
        putString(EXTRA_CLIENT_NONCE, nonce)
    }

    private fun pruneLocked() {
        val now = clock()
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
    private val AUTH_ACTIVITY: String get() = AutofillAuthActivity::class.java.name
}

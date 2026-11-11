package org.locklark.android.autofill

import android.view.autofill.AutofillId
import org.locklark.android.security.NativeCallFailure
import org.locklark.android.security.NativeFailures
import org.locklark.android.security.NativePhase
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * Exact native target: the OS package and both OS AutofillIds of this one
 * authentication request. Equality uses AutofillId's identity semantics.
 */
internal class AutofillTarget private constructor(
    val packageName: String,
    val usernameId: AutofillId,
    val passwordId: AutofillId,
) {
    fun matches(form: LoginForm?): Boolean =
        form != null && form.packageName == packageName &&
            form.usernameId.equals(usernameId) && form.passwordId.equals(passwordId)

    override fun equals(other: Any?): Boolean =
        other is AutofillTarget && packageName == other.packageName &&
            usernameId.equals(other.usernameId) && passwordId.equals(other.passwordId)

    override fun hashCode(): Int =
        31 * (31 * packageName.hashCode() + usernameId.hashCode()) + passwordId.hashCode()

    override fun toString(): String = "[autofill target]"

    companion object {
        fun from(form: LoginForm): AutofillTarget =
            AutofillTarget(form.packageName, form.usernameId, form.passwordId)
    }
}

/**
 * One active login row as listed. Only metadata is retained: no username,
 * password or other field value. The title is bounded and stripped of control
 * and format code points before it is ever shown.
 */
internal class ActiveLogin private constructor(
    val rowId: String,
    val rowRevision: String,
    val shownTitle: String,
) {
    /** The only form selection may use: the visible, sanitized title. */
    override fun toString(): String = shownTitle

    companion object {
        private const val MAX_TITLE_CODE_POINTS = 120
        private const val EMPTY_TITLE = "（空标题）"

        /**
         * Null unless the row is active and carries a row ID and revision. The
         * exact strings are kept for the later approve revalidation.
         */
        fun of(rowId: String?, rowRevision: String?, state: String?, title: String?): ActiveLogin? {
            if (state != "active") return null
            if (rowId.isNullOrEmpty() || rowRevision.isNullOrEmpty()) return null
            return ActiveLogin(rowId, rowRevision, sanitizeTitle(title))
        }

        fun sanitizeTitle(value: String?): String = buildString {
            value.orEmpty().codePoints().limit(MAX_TITLE_CODE_POINTS.toLong()).forEach { cp ->
                if (Character.isISOControl(cp) || Character.getType(cp) == Character.FORMAT.toInt()) {
                    append("\\u{%X}".format(cp))
                } else {
                    appendCodePoint(cp)
                }
            }
        }.ifEmpty { EMPTY_TITLE }
    }
}

/**
 * The single explicit, one-use approval produced by AutofillAuthActivity and
 * bound to [target] plus one exact vault row ID/revision. Unlock factors are
 * deliberately absent. Username/password exist only as private mutable byte
 * buffers, the value can be taken once, and clearing zeroes them. Clear is pure
 * buffer cleanup: it takes no callback and never mutates UI, logging or disk.
 * Diagnostics are redacted.
 */
internal class ApprovedAutofillResult private constructor(
    val target: AutofillTarget,
    val rowId: String,
    val rowRevision: String,
) {
    private val lock = Any()
    // Private copies, zeroed in place before the reference is dropped.
    private var username: ByteArray? = null
    private var password: ByteArray? = null
    private var consumed = false

    /** Row identity only, no credential bytes. Null once the approval is gone. */
    val binding: RowBinding? get() = synchronized(lock) {
        if (consumed) null else RowBinding(rowId, rowRevision)
    }

    fun isConsumed(): Boolean = synchronized(lock) { consumed }

    fun targetMatches(form: LoginForm?): Boolean = target.matches(form)

    /** Returns a private copy once, then zeroes the internal buffers. */
    fun take(): AutofillCredentialBytes? = synchronized(lock) {
        if (consumed) return null
        val user = username ?: return null
        val pass = password ?: return null
        consumed = true
        val snapshot = AutofillCredentialBytes.copyOf(user, pass)
        wipeLocked()
        snapshot
    }

    /** Idempotent: zeroes both buffers, so no later take can succeed. */
    fun clear() = synchronized(lock) {
        consumed = true
        wipeLocked()
    }

    private fun wipeLocked() {
        username?.fill(0)
        password?.fill(0)
        username = null
        password = null
    }

    override fun toString(): String = synchronized(lock) {
        "ApprovedAutofillResult(target=$target, " +
            "binding=${if (consumed) "null" else "RowBinding(id=$rowId, revision=$rowRevision)"}, " +
            "consumed=$consumed)"
    }

    companion object {
        fun create(
            target: AutofillTarget,
            rowId: String,
            rowRevision: String,
            username: ByteArray,
            password: ByteArray,
        ): ApprovedAutofillResult = ApprovedAutofillResult(
            target = target,
            rowId = rowId,
            rowRevision = rowRevision,
        ).also {
            it.username = username.copyOf()
            it.password = password.copyOf()
        }
    }
}

internal data class RowBinding(val id: String, val revision: String)

/** Caller-owned credential copy; [clear] zeroes it. Never printable. */
internal class AutofillCredentialBytes private constructor(
    private val username: ByteArray,
    private val password: ByteArray,
) {
    fun copyUsername(): ByteArray = username.copyOf()
    fun copyPassword(): ByteArray = password.copyOf()

    fun clear() {
        username.fill(0)
        password.fill(0)
    }

    override fun equals(other: Any?): Boolean =
        other is AutofillCredentialBytes && username.contentEquals(other.username) && password.contentEquals(other.password)

    override fun hashCode(): Int = 31 * username.contentHashCode() + password.contentHashCode()
    override fun toString(): String = "[autofill credential bytes]"

    companion object {
        internal fun copyOf(username: ByteArray, password: ByteArray): AutofillCredentialBytes =
            AutofillCredentialBytes(username.copyOf(), password.copyOf())
    }
}

/**
 * The one factor access used by the approval lane's unlock. The Activity hands
 * the worker copy of the master password to [unlock]; the implementation
 * zeroes it and its own buffers on every path. Tests substitute a synthetic
 * implementation so no credential String is ever created on the JVM.
 */
internal interface MobilecoreGateway {
    /**
     * @param password the caller-owned master password; the gateway encodes it
     *   to UTF-8, zeroes it, and fills every byte buffer before returning/throwing.
     * @param secretKey the caller-owned Secret Key text; same contract.
     */
    fun unlock(outcome: ApprovalOutcome, password: CharArray, secretKey: CharArray)
}

/** The only outcomes the approval lane acts on. */
internal class ApprovalOutcome {
    @Volatile var failure: NativeCallFailure? = null

    fun fail(error: Throwable) {
        if (failure == null) failure = NativeFailures.failure(NativePhase.UNLOCK, error)
    }

    override fun toString(): String = "[approval outcome]"
}

/** Factor encoding helpers with no stored copy. */
internal object ApprovalSecret {
    /**
     * Strict UTF-8 encoding: an unpaired surrogate is an invalid factor and
     * yields an empty array, which the caller rejects. Never a lossy copy.
     */
    fun encodeUtf8(value: CharArray): ByteArray = try {
        val encoded = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(CharBuffer.wrap(value))
        ByteArray(encoded.remaining()).also { encoded.get(it) }
    } catch (_: CharacterCodingException) {
        ByteArray(0)
    }
}

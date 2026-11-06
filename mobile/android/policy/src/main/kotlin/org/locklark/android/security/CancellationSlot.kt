package org.locklark.android.security

/** Publish a native operation atomically with its lifecycle validity check. */
class CancellationSlot<T>(private val cancelValue: (T) -> Unit) {
    private val lock = Any()
    private var value: T? = null

    fun publish(next: T, current: () -> Boolean): Boolean {
        var previous: T? = null
        val accepted = synchronized(lock) {
            if (!current()) false
            else { previous = value; value = next; true }
        }
        previous?.let(cancelValue)
        if (!accepted) cancelValue(next)
        return accepted
    }

    fun cancel() {
        val previous = synchronized(lock) { value.also { value = null } }
        // Never invoke a platform callback while holding the publication lock.
        previous?.let(cancelValue)
    }
}

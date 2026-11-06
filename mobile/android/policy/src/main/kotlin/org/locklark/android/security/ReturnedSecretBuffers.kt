package org.locklark.android.security

/** Mutable JNI callback results live only until their enclosing core call ends. */
class ReturnedSecretBuffers {
    private val lock = Any()
    private val values = mutableListOf<ByteArray>()
    private var released = false

    fun retain(value: ByteArray): ByteArray = synchronized(lock) {
        if (released) { value.fill(0); throw ObsoleteWork() }
        values.add(value)
        value
    }

    /** Caller invokes this after the synchronous Go call returns, never earlier. */
    fun clearAfterCall() {
        val pending = synchronized(lock) {
            if (released) return
            released = true
            values.toList().also { values.clear() }
        }
        pending.forEach { it.fill(0) }
    }
}

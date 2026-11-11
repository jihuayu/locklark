package org.locklark.android.autofill

/**
 * Decides, under one lock, whether a freshly opened vault is installed or
 * dropped, and whether a terminal close has already been scheduled. The worker
 * requests a close; the main thread handles the open result. Neither can
 * overtake the other: after the first code asks to cancel, every later open
 * result is rejected here without any main-thread bookkeeping.
 */
internal class FreshVaultGate {
    private enum class State { IDLE, OPENING, OPEN, EXITED }

    private val lock = Any()
    private var state = State.IDLE
    private var closeScheduled = false

    /** Starts the one-shot open; false when an open already ran or exit began. */
    @Synchronized fun beginOpen(): Boolean {
        if (state != State.IDLE) return false
        state = State.OPENING
        return true
    }

    /**
     * Accepts the opened vault exactly once while opening. Any other outcome
     * (already open, exited, duplicate result) says drop it on the worker.
     */
    @Synchronized fun install(): Boolean {
        if (state != State.OPENING) return false
        state = State.OPEN
        return true
    }

    /**
     * Terminal. Returns true exactly once, for the first caller, which must
     * then requestLock and close the vault on its serialized worker; a late
     * open result is always rejected by [install].
     */
    @Synchronized fun exit(): Boolean {
        state = State.EXITED
        if (closeScheduled) return false
        closeScheduled = true
        return true
    }

    /** An open that failed (or was rejected) never leaves an installable vault. */
    @Synchronized fun openFailed() {
        if (state == State.OPENING) state = State.IDLE
    }

    override fun toString(): String = synchronized(lock) {
        "[fresh vault gate ${state.name.lowercase()} closeScheduled=$closeScheduled]"
    }
}

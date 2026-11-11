package org.locklark.android.autofill

import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

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
    private var closeAction = CloseAction.NONE

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
     * then call [release] on the main thread.
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

    /**
     * The one terminal release, decided under this gate's lock: [vault] was
     * accepted by [install] and already installed on the serialized [worker].
     * Requests the vault lock now on the calling (main) thread, then enqueues
     * the single close on that worker behind any in-flight open, unlock, list
     * or reveal.
     *
     * Invariant: the vault is only ever closed on the worker that created and
     * serialized it, never on main. [close] is queued, so a worker that is
     * still running it will run it before shutdown completes. If [worker]
     * rejects the close, it is already shut down and can run no native call at
     * all; only then is the lock requested without a close, so this path never
     * touches the vault from the main thread beyond [lock].
     *
     * Late installs are left to [install], which rejects them, and the worker
     * that finished [org.locklark.android.autofill.AutofillAuthActivity]'s open
     * requests the lock and closes the dropped vault there itself.
     */
    @Synchronized fun <V> release(vault: V, worker: Executor, lock: (V) -> Unit, close: (V) -> Unit) {
        // release() runs once, from the single exit() winner and on main.
        closeAction = CloseAction.WORKER_CLOSE
        lock(vault)
        try {
            worker.execute { close(vault) }
        } catch (_: RejectedExecutionException) {
            closeAction = CloseAction.LOCK_ONLY
        }
    }

    /** How the first [exit] released an installed vault; [CloseAction.NONE] before it. */
    @Synchronized fun closeDecision(): CloseAction = closeAction

    override fun toString(): String = synchronized(lock) {
        "[fresh vault gate ${state.name.lowercase()} closeScheduled=$closeScheduled close=${closeAction.name.lowercase()}]"
    }
}

/** How [FreshVaultGate.release] releases a vault that was already installed. */
internal enum class CloseAction {
    /** Nothing installed yet; a late open result is dropped on the worker itself. */
    NONE,

    /** Installed on the worker: the single close runs there as its next task. */
    WORKER_CLOSE,

    /** Installed, but the worker already shut down: lock requested, never closed off-worker. */
    LOCK_ONLY,
}

/**
 * The fixed state of this one-use handoff on the main thread. Main-thread only.
 * A terminal exit is never undone; once the database was missing, the
 * handoff stays unavailable and is never opened again.
 */
internal class LifecycleState {
    enum class Terminal { NONE, CANCELLED, UNAVAILABLE }

    var terminal: Terminal = Terminal.NONE
        private set

    /** The database was missing at onCreate: fixed unavailable, never opened. */
    var databaseMissing = false
        private set

    val isTerminal: Boolean get() = terminal != Terminal.NONE

    /** Marks the missing-database branch; false if the handoff already ended. */
    fun markDatabaseMissing(): Boolean {
        if (isTerminal) return false
        databaseMissing = true
        return true
    }

    /** One-shot transition to a terminal state; false if one already happened. */
    fun end(next: Terminal): Boolean {
        if (isTerminal) return false
        terminal = next
        return true
    }
}

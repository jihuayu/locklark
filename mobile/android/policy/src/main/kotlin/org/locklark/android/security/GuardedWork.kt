package org.locklark.android.security

/** Worker invocation with explicit ownership of native mutable input copies. */
class ObsoleteWork : Exception("Native work is no longer current")

object GuardedWork {
    fun ensureCurrent(gate: ForegroundGate, stamp: WorkStamp, target: Target? = null) {
        if (!gate.accepts(stamp, target)) throw ObsoleteWork()
    }
    fun <T> run(gate: ForegroundGate, stamp: WorkStamp, target: Target?, clearInputs: () -> Unit, task: () -> T): T {
        try { ensureCurrent(gate, stamp, target); return task() }
        finally { clearInputs() }
    }
}

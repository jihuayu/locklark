package org.locklark.android.security

/** Public target metadata; no disclosed values or unlock factors. */
data class Target(val id: String, val revision: String, val field: String)
data class WorkStamp internal constructor(val epoch: Long, val operation: Long, val target: Target?)

/** A late worker or OS-auth callback never restores a backgrounded UI. */
class ForegroundGate {
    private var foreground = false
    private var epoch = 0L
    private var operation = 0L

    @Synchronized fun isForeground(): Boolean = foreground
    @Synchronized fun start() { foreground = true; epoch++ }
    @Synchronized fun stop() { foreground = false; epoch++; operation++ }
    @Synchronized fun invalidate() { epoch++; operation++ }
    @Synchronized fun begin(target: Target? = null): WorkStamp {
        check(foreground)
        return WorkStamp(epoch, ++operation, target)
    }
    @Synchronized fun accepts(stamp: WorkStamp, target: Target? = null): Boolean =
        foreground && epoch == stamp.epoch && operation == stamp.operation && stamp.target == target
}

/** Check core wall-clock bounds once, then clear using an elapsed-time budget. */
class SecretDeadline private constructor(private val sampledElapsed: Long, private val deadlineElapsed: Long) {
    fun validAt(elapsed: Long): Boolean = elapsed >= sampledElapsed && elapsed < deadlineElapsed
    fun remainingAt(elapsed: Long): Long = if (validAt(elapsed)) deadlineElapsed - elapsed else 0

    companion object {
        fun create(fromUnixMillis: Long, untilUnixMillis: Long, wallMillis: Long, elapsedMillis: Long): SecretDeadline? {
            if (fromUnixMillis > wallMillis || wallMillis >= untilUnixMillis || elapsedMillis < 0) return null
            val remaining = try { Math.subtractExact(untilUnixMillis, wallMillis) } catch (_: ArithmeticException) { return null }
            val deadline = try { Math.addExact(elapsedMillis, minOf(remaining, 15_000)) } catch (_: ArithmeticException) { return null }
            return SecretDeadline(elapsedMillis, deadline)
        }
    }
}

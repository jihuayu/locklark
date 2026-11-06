package org.locklark.android.security

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class GuardedWorkTest {
    @Test fun queuedUnlockCreateAndEditNeverReachCoreAfterBackground() {
        for (operation in listOf("unlock", "create", "edit")) {
            val gate = ForegroundGate(); gate.start()
            val target = if (operation == "edit") Target("id", "revision", "password") else null
            val stamp = gate.begin(target)
            val inputs = listOf("private-password", "private-key", "private-value").map { it.toByteArray() }
            val calls = AtomicInteger()
            val entered = CountDownLatch(1); val release = CountDownLatch(1)
            val worker = Executors.newSingleThreadExecutor()
            try {
                worker.submit { entered.countDown(); check(release.await(2, TimeUnit.SECONDS)) }
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                val pending = worker.submit {
                    runCatching {
                        GuardedWork.run(gate, stamp, target, { inputs.forEach { it.fill(0) } }) { calls.incrementAndGet() }
                    }
                }
                gate.stop(); release.countDown(); pending.get(2, TimeUnit.SECONDS)
                assertEquals("Obsolete native operation reached core", 0, calls.get())
                assertTrue("Rejected inputs retained", inputs.all { input -> input.all { it == 0.toByte() } })
            } finally { release.countDown(); worker.shutdownNow() }
        }
    }

    @Test fun inputCleanupAlsoRunsWhenCoreThrows() {
        val gate = ForegroundGate(); gate.start(); val stamp = gate.begin()
        val input = byteArrayOf(1,2,3)
        runCatching { GuardedWork.run(gate, stamp, null, { input.fill(0) }) { error("fixed failure") } }
        assertTrue(input.all { it == 0.toByte() })
    }
}

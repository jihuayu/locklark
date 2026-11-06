package org.locklark.android.security

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class CancellationSlotTest {
    @Test fun promptCreatedAfterStopIsImmediatelyCancelled() {
        val gate = ForegroundGate(); gate.start(); val stamp = gate.begin()
        val cancelled = AtomicInteger()
        val slot = CancellationSlot<Any> { cancelled.incrementAndGet() }
        gate.stop(); slot.cancel()
        assertFalse(slot.publish(Any()) { gate.accepts(stamp) })
        assertEquals(1, cancelled.get())
    }

    @Test fun stopBetweenCurrentCheckAndPublicationStillCancels() {
        val gate = ForegroundGate(); gate.start(); val stamp = gate.begin()
        val checked = CountDownLatch(1); val release = CountDownLatch(1)
        val cancelled = AtomicInteger()
        val slot = CancellationSlot<Any> { cancelled.incrementAndGet() }
        val publisher = Thread {
            slot.publish(Any()) {
                val current = gate.accepts(stamp)
                checked.countDown()
                check(release.await(2, TimeUnit.SECONDS))
                current
            }
        }
        publisher.start(); assertTrue(checked.await(2, TimeUnit.SECONDS))
        gate.stop()
        val stopper = Thread { slot.cancel() }.apply { start() }
        release.countDown(); publisher.join(2000); stopper.join(2000)
        assertFalse(publisher.isAlive); assertFalse(stopper.isAlive)
        assertEquals(1, cancelled.get())
    }
}

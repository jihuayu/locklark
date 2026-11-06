package org.locklark.android.security

import org.junit.Assert.*
import org.junit.Test

class ForegroundGateTest {
    private val a = Target("a", "r1", "password")
    private val b = Target("a", "r2", "password")

    @Test fun backgroundRejectsLateUnlockAndDisclosure() {
        val gate = ForegroundGate()
        gate.start()
        val work = gate.begin(a)
        assertTrue(gate.accepts(work, a))
        gate.stop()
        assertFalse(gate.accepts(work, a))
        gate.start()
        assertFalse(gate.accepts(work, a))
    }

    @Test fun revisionFieldAndOperationMustAllMatch() {
        val gate = ForegroundGate()
        gate.start()
        val old = gate.begin(a)
        assertFalse(gate.accepts(old, b))
        assertFalse(gate.accepts(old, a.copy(field = "notes")))
        val current = gate.begin(b)
        assertFalse(gate.accepts(old, a))
        assertTrue(gate.accepts(current, b))
    }

    @Test fun selectionRevokesPendingWorkEvenWithinSameForeground() {
        val gate = ForegroundGate()
        gate.start()
        val work = gate.begin(a)
        gate.invalidate()
        assertFalse(gate.accepts(work, a))
        assertTrue(gate.accepts(gate.begin(b), b))
    }

    @Test fun leaseChecksStartAndEndAndUsesBoundedMonotonicDeadline() {
        assertNull(SecretDeadline.create(100, 200, 99, 1000))
        assertNull(SecretDeadline.create(100, 200, 200, 1000))
        assertNull(SecretDeadline.create(100, 99, 150, 1000))
        val clipped = SecretDeadline.create(100, 1_000_000, 150, 1000)!!
        assertTrue(clipped.validAt(15_999))
        assertFalse(clipped.validAt(16_000))
        assertFalse(clipped.validAt(999))
        val otp = SecretDeadline.create(100, 200, 150, 1000)!!
        assertTrue(otp.validAt(1049))
        assertFalse(otp.validAt(1050))
    }
}

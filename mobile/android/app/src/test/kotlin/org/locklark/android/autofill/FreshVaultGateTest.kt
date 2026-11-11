package org.locklark.android.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The open/exit race: whichever side runs first, an open result obtained after
 * a terminal exit is never installable, and exactly one close is scheduled.
 */
class FreshVaultGateTest {
    @Test
    fun openOnlyRunsOnceAndInstallsOnce() {
        val gate = FreshVaultGate()
        assertTrue(gate.beginOpen())
        assertFalse("a second onStart never reopens", gate.beginOpen())
        assertTrue(gate.install())
        assertFalse("a duplicate open result is dropped", gate.install())
        assertTrue(gate.exit())
        assertFalse(gate.exit())
    }

    @Test
    fun lateOpenResultAfterExitIsRejected() {
        val gate = FreshVaultGate()
        assertTrue(gate.beginOpen())
        // onStop arrives while Mobilecore.open is still running.
        assertTrue("the exit requests the one close", gate.exit())
        assertFalse("the late result must be dropped on the worker", gate.install())
        assertFalse("nothing is opened again after stop", gate.beginOpen())
        assertFalse("no second close is ever scheduled", gate.exit())
    }

    @Test
    fun installAfterExitInEitherOrderStillClosesExactlyOnce() {
        // Main-side exit first, then the worker's install attempt.
        val exitFirst = FreshVaultGate()
        exitFirst.beginOpen()
        val closedByExit = exitFirst.exit()
        val installed = exitFirst.install()
        assertTrue(closedByExit)
        assertFalse(installed)
        assertFalse(exitFirst.exit())

        // Worker installs first, then onStop's exit owns the close.
        val installFirst = FreshVaultGate()
        installFirst.beginOpen()
        assertTrue(installFirst.install())
        assertTrue("an installed vault is closed by the exit", installFirst.exit())
        assertFalse(installFirst.exit())
    }

    @Test
    fun failedOpenLeavesNothingInstallable() {
        val gate = FreshVaultGate()
        assertTrue(gate.beginOpen())
        gate.openFailed()
        assertFalse("a failed open never installs", gate.install())
        assertTrue("exit still schedules the worker teardown", gate.exit())
        assertFalse(gate.exit())
    }
}

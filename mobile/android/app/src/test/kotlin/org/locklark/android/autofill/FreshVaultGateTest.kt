package org.locklark.android.autofill

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
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

/** A terminal release, modeled on the vault's observable calls. */
class FreshVaultReleaseTest {
    private class FakeVault {
        val calls = mutableListOf<String>()

        fun requestLock() {
            calls += "lock"
        }

        fun close() {
            calls += "close"
        }
    }

    private fun gate(): FreshVaultGate = FreshVaultGate().apply {
        assertTrue(beginOpen())
        assertTrue(install())
    }

    @Test
    fun lockIsSynchronousAndCloseRunsOnceOnTheWorker() {
        val gate = gate()
        val vault = FakeVault()
        val worker = Executor { it.run() }
        gate.release(vault, worker, { it.requestLock() }, { it.close() })
        assertEquals(listOf("lock", "close"), vault.calls)
        assertEquals(CloseAction.WORKER_CLOSE, gate.closeDecision())
        // onStop already owned the exit; onDestroy/back/cancel release nothing.
        assertTrue(gate.exit())
        assertFalse("only the first exit releases", gate.exit())
    }

    @Test
    fun refusedWorkerNeverClosesOnTheCallingThread() {
        val gate = gate()
        val vault = FakeVault()
        val shutDown = Executor { throw RejectedExecutionException("shut down") }
        gate.release(vault, shutDown, { it.requestLock() }, { it.close() })
        assertEquals("the lock is requested, the close is not run off-worker", listOf("lock"), vault.calls)
        assertEquals(CloseAction.LOCK_ONLY, gate.closeDecision())
    }

    @Test
    fun closeWaitsBehindAlreadyQueuedWorkButTheLockDoesNot() {
        val base = Executors.newSingleThreadExecutor()
        try {
            val gate = gate()
            val vault = FakeVault()
            val queued = CountDownLatch(1)
            val releaseQueued = CountDownLatch(1)
            base.execute {
                queued.countDown()
                releaseQueued.await()
            }
            assertTrue(queued.await(5, TimeUnit.SECONDS))
            gate.release(vault, base, { it.requestLock() }, { it.close() })
            assertEquals("the lock never waits for queued work", listOf("lock"), vault.calls)
            releaseQueued.countDown()
            base.shutdown()
            assertTrue(base.awaitTermination(5, TimeUnit.SECONDS))
            assertEquals("the close stays on the serialized worker", listOf("lock", "close"), vault.calls)
        } finally {
            base.shutdownNow()
        }
    }
}

/**
 * The main-thread handoff state: a terminal exit is one-shot, and a missing
 * database latches so a later onStart can never open or show the factors UI.
 */
class LifecycleStateTest {
    @Test
    fun missingDatabaseIsFixedUnavailableOnLaterStarts() {
        val state = LifecycleState()
        assertTrue(state.markDatabaseMissing())
        assertTrue(state.databaseMissing)
        assertFalse("no exit latched yet", state.isTerminal)
        // A later onStart consults databaseMissing, never beginOpen.
        assertTrue(state.markDatabaseMissing())
    }

    @Test
    fun terminalExitWinsOverLateEventsExactlyOnce() {
        val state = LifecycleState()
        assertTrue(state.end(LifecycleState.Terminal.CANCELLED))
        assertTrue(state.isTerminal)
        assertFalse("onDestroy/back/cancel never re-finish", state.end(LifecycleState.Terminal.UNAVAILABLE))
        assertFalse("a later onStart never reopens", state.markDatabaseMissing())
        assertEquals(LifecycleState.Terminal.CANCELLED, state.terminal)
    }

    @Test
    fun missingDatabaseRefusalEndsTheHandoff() {
        val state = LifecycleState()
        assertTrue(state.markDatabaseMissing())
        assertTrue(state.end(LifecycleState.Terminal.UNAVAILABLE))
        assertTrue(state.isTerminal)
        assertEquals(LifecycleState.Terminal.UNAVAILABLE, state.terminal)
    }
}

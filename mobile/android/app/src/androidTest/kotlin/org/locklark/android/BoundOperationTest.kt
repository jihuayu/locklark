package org.locklark.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import mobilecore.Mobilecore
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.locklark.android.security.ForegroundGate
import org.locklark.android.security.GuardedWork
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Actual JNI/core call after a successful native preflight, not a mock core. */
@RunWith(AndroidJUnit4::class)
class BoundOperationTest {
    @Test fun cancellationBetweenPreflightAndGoCannotCreateDatabase() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_stage", "bound-operation") })
        val root = instrumentation.targetContext.cacheDir
        val fixture = File(root, "instrumentation-canaries.json")
        val canaries = if (fixture.exists()) JSONArray(fixture.readText()) else JSONArray()
        val password = "Bound-Password-" + UUID.randomUUID()
        val accountKey = "FixtureKey123456"
        canaries.put(password); canaries.put(accountKey)
        fixture.writeText(canaries.toString())
        val path = File(root, "bound-operation-" + UUID.randomUUID() + ".ll")
        val base = Mobilecore.open(path.absolutePath)
        lateinit var captured: mobilecore.Vault
        val gate = ForegroundGate(); gate.start()
        instrumentation.runOnMainSync { captured = base.captureOperation() }
        val stamp = gate.begin()
        val checked = CountDownLatch(1); val release = CountDownLatch(1)
        val pw = password.toByteArray(); val key = accountKey.toByteArray()
        val worker = Executors.newSingleThreadExecutor()
        try {
            val result = worker.submit<Boolean> {
                runCatching {
                    GuardedWork.run(gate, stamp, null, { pw.fill(0); key.fill(0) }) {
                        checked.countDown()
                        check(release.await(5,TimeUnit.SECONDS))
                        captured.create(pw,key)
                    }
                }.isFailure
            }
            assertTrue("Preflight barrier unavailable", checked.await(5,TimeUnit.SECONDS))
            instrumentation.runOnMainSync { gate.stop(); base.requestLock() }
            release.countDown()
            assertTrue("Stale captured Go operation was accepted", result.get(10,TimeUnit.SECONDS))
            assertFalse("Cancelled creation wrote a database", path.exists())
            assertTrue("Cancelled factor buffers retained", pw.all { it == 0.toByte() } && key.all { it == 0.toByte() })
        } finally {
            release.countDown(); base.requestLock(); worker.shutdownNow(); base.close()
            pw.fill(0); key.fill(0)
        }
    }
}

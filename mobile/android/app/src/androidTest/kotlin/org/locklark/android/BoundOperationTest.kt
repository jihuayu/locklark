package org.locklark.android

import android.content.ContextWrapper
import android.system.Os
import android.system.OsConstants
import android.system.ErrnoException
import android.util.AtomicFile
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import mobilecore.Mobilecore
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.locklark.android.security.ForegroundGate
import org.locklark.android.security.GuardedWork
import org.locklark.android.security.NativeFailures
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
        // This is a real Android AtomicFile first write, before any OS auth.
        // The isolated Context changes only the test's private storage root.
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_stage", "capsule-storage") })
        val isolated = File(root, "capsule-storage-" + UUID.randomUUID()).apply { mkdirs() }
        val context = object : ContextWrapper(instrumentation.targetContext) {
            override fun getNoBackupFilesDir(): File = isolated
        }
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            lateinit var activity: MainActivity
            scenario.onActivity { activity = it }
            val prompt = NativeCryptoPrompt(activity) { false }
            // Demonstrate the old pathname chmod failure on the real platform.
            val legacy = AtomicFile(File(isolated, "legacy-installation"))
            val staging = legacy.startWrite()
            try {
                val wrongPath = runCatching { Os.chmod(legacy.baseFile.path, 384) }.exceptionOrNull()
                assertTrue("First AtomicFile write must use staging FD", wrongPath is ErrnoException && wrongPath.errno == OsConstants.ENOENT)
            } finally { legacy.failWrite(staging) }
            PlatformCapsuleStore(context, prompt) { false }
            val installation = File(isolated, "device-unlock/installation")
            assertTrue("Private installation metadata absent", installation.isFile)
            assertTrue("Committed installation permissions invalid", Os.stat(installation.path).st_mode and 511 == 384)
            assertTrue("Private capsule directory permissions invalid", Os.stat(installation.parentFile!!.path).st_mode and 511 == 448)
            val original = installation.readText()
            assertTrue("Private installation metadata invalid", original.matches(Regex("[0-9a-f-]{36}")))
            assertFalse("Atomic staging file retained", File(installation.path + ".new").exists())
            PlatformCapsuleStore(context, prompt) { false }
            assertTrue("Existing installation changed", installation.readText() == original)
        } finally { scenario.close() }
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_stage", "bound-operation") })
        val fixture = File(root, "instrumentation-canaries.json")
        val canaries = if (fixture.exists()) JSONArray(fixture.readText()) else JSONArray()
        val password = "Bound-Password-" + UUID.randomUUID()
        val accountKey = "FixtureKey123456"
        canaries.put(password); canaries.put(accountKey)
        fixture.writeText(canaries.toString())
        val appRoot = instrumentation.targetContext.noBackupFilesDir
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_stage", "platform-fs") })
        val fs = File(appRoot, "fs-probe-" + UUID.randomUUID()).apply { mkdirs() }
        val source = File(fs,"source"); val linked = File(fs,"linked")
        try {
            source.outputStream().use { it.write("public-fs-probe".toByteArray()) }
            Os.chmod(source.path,384)
            val owned = Os.stat(source.path).st_uid == android.os.Process.myUid()
            var linkOkay = false
            var linkErrno = 0
            try { Os.link(source.path,linked.path); linkOkay = linked.readText() == "public-fs-probe" }
            catch (error: ErrnoException) { linkErrno = error.errno }
            instrumentation.sendStatus(0, android.os.Bundle().apply {
                putString("locklark_fs_owned",owned.toString())
                putString("locklark_fs_link",linkOkay.toString())
                putString("locklark_fs_errno",linkErrno.toString())
            })
            val directory = Os.open(fs.path,OsConstants.O_RDONLY,0)
            try {
                assertTrue("Native parent FD must be a directory",Os.fstat(directory).st_mode and OsConstants.S_IFMT == OsConstants.S_IFDIR)
                Os.fsync(directory)
            } finally { Os.close(directory) }
            assertTrue("Native private source must be owned",owned)
            // Report unsupported hard links without hiding the real JNI result.
            // The core's selected atomic publication primitive must still work.
        } finally { source.delete(); linked.delete(); fs.delete() }

        // Positive actual JNI calls use the same two-copy pattern as the UI.
        val positivePath = File(appRoot,"positive-jni-" + UUID.randomUUID() + ".ll")
        val positive = Mobilecore.open(positivePath.absolutePath)
        lateinit var api: mobilecore.Vault
        instrumentation.runOnMainSync { api = positive.captureOperation() }
        val positivePassword = password.toByteArray(); val positiveKey = accountKey.toByteArray()
        val createPassword = positivePassword.copyOf(); val createKey = positiveKey.copyOf()
        try {
            instrumentation.sendStatus(0, android.os.Bundle().apply {
                putString("locklark_stage","binding-create"); putString("locklark_core_phase","create")
            })
            try { api.create(createPassword,createKey) }
            catch (error: Exception) {
                instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_core_error",NativeFailures.classify(error).name.lowercase()) })
                throw AssertionError("Positive JNI creation refused")
            }
            val intact = positivePassword.contentEquals(password.toByteArray()) && positiveKey.contentEquals(accountKey.toByteArray())
            instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_inputs_intact",intact.toString()) })
            assertTrue("JNI changed unrelated caller factor buffers", intact)
            instrumentation.sendStatus(0, android.os.Bundle().apply {
                putString("locklark_stage","binding-unlock"); putString("locklark_core_phase","unlock")
            })
            try { api.unlock(positivePassword,positiveKey) }
            catch (error: Exception) {
                instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_core_error",NativeFailures.classify(error).name.lowercase()) })
                throw AssertionError("Positive JNI unlock refused")
            }
            assertTrue("Positive JNI vault not unlocked",positive.isUnlocked())
            assertTrue("Positive JNI authenticated list invalid",api.list("active").count() == 0L)
        } finally {
            positivePassword.fill(0); positiveKey.fill(0); createPassword.fill(0); createKey.fill(0)
            positive.requestLock(); positive.close()
        }
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_stage","bound-operation") })
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

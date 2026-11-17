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
import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
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
        val capsuleName = "capsule-storage-" + UUID.randomUUID()
        val isolated = File(root, capsuleName).apply { mkdirs() }
        val context = object : ContextWrapper(instrumentation.targetContext) {
            override fun getNoBackupFilesDir(): File = isolated
        }
        var scenario: ActivityScenario<MainActivity>? = null
        var scenarioFailure: Throwable? = null
        try {
            val launched = ActivityScenario.launch(MainActivity::class.java)
            scenario = launched
            lateinit var activity: MainActivity
            launched.onActivity { activity = it }
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
        } catch (error: Throwable) {
            scenarioFailure = error
            throw error
        } finally {
            // The isolated tree belongs only to this UUID; the Activity never
            // reads it after the scenario is closed.
            runCleanup(scenarioFailure,
                { scenario?.close() },
                { deleteOwnedCapsuleTree(root, capsuleName) })
        }
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
        val positiveName = "positive-jni-" + UUID.randomUUID() + ".ll"
        val positivePath = File(appRoot, positiveName)
        val positive = Mobilecore.open(positivePath.absolutePath)
        lateinit var api: mobilecore.Vault
        val positivePassword = password.toByteArray(); val positiveKey = accountKey.toByteArray()
        val createPassword = positivePassword.copyOf(); val createKey = positiveKey.copyOf()
        var positiveFailure: Throwable? = null
        try {
            instrumentation.runOnMainSync { api = positive.captureOperation() }
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
        } catch (error: Throwable) {
            positiveFailure = error
            throw error
        } finally {
            positivePassword.fill(0); positiveKey.fill(0); createPassword.fill(0); createKey.fill(0)
            // Lock and close the native handle before removing only this
            // synthetic vault and its exact AtomicFile-style sidecars.
            runCleanup(positiveFailure,
                { positive.requestLock() },
                { positive.close() },
                { deleteOwnedFile(positivePath, appRoot, positiveName, listOf(".new", ".bak")) })
        }
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_stage","bound-operation") })
        val negativeName = "bound-operation-" + UUID.randomUUID() + ".ll"
        val path = File(root, negativeName)
        val base = Mobilecore.open(path.absolutePath)
        val checked = CountDownLatch(1); val release = CountDownLatch(1)
        val pw = password.toByteArray(); val key = accountKey.toByteArray()
        val worker = Executors.newSingleThreadExecutor()
        var negativeFailure: Throwable? = null
        var gate: ForegroundGate? = null
        try {
            val foreground = ForegroundGate().also { it.start() }
            gate = foreground
            lateinit var captured: mobilecore.Vault
            instrumentation.runOnMainSync { captured = base.captureOperation() }
            val stamp = foreground.begin()
            val result = worker.submit<Boolean> {
                runCatching {
                    GuardedWork.run(foreground, stamp, null, { pw.fill(0); key.fill(0) }) {
                        checked.countDown()
                        check(release.await(5,TimeUnit.SECONDS))
                        captured.create(pw,key)
                    }
                }.isFailure
            }
            assertTrue("Preflight barrier unavailable", checked.await(5,TimeUnit.SECONDS))
            instrumentation.runOnMainSync { foreground.stop(); base.requestLock() }
            release.countDown()
            assertTrue("Stale captured Go operation was accepted", result.get(10,TimeUnit.SECONDS))
            assertFalse("Cancelled creation wrote a database", path.exists())
            assertTrue("Cancelled factor buffers retained", pw.all { it == 0.toByte() } && key.all { it == 0.toByte() })
        } catch (error: Throwable) {
            negativeFailure = error
            throw error
        } finally {
            release.countDown()
            pw.fill(0); key.fill(0)
            // The base handle is locked and closed before the exact negative
            // path is removed, including after a failed or partial operation.
            runCleanup(negativeFailure,
                { if (gate != null) instrumentation.runOnMainSync { gate?.stop() } },
                { base.requestLock() },
                { worker.shutdownNow() },
                { base.close() },
                { deleteOwnedFile(path, root, negativeName, listOf(".new", ".bak")) })
        }
    }

    /**
     * Runs ordered cleanup steps. A cleanup failure becomes the test failure
     * only when the body did not already fail; otherwise it is attached as a
     * suppressed exception so the original assertion stays visible.
     */
    private fun runCleanup(primary: Throwable?, vararg steps: () -> Unit) {
        var failure: Throwable? = null
        for (step in steps) {
            try {
                step()
            } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
        }
        val cleanupFailure = failure ?: return
        if (primary == null) throw cleanupFailure
        primary.addSuppressed(cleanupFailure)
    }

    /** Removes only [expectedName] under [parent] plus its exact sidecars. */
    private fun deleteOwnedFile(path: File, parent: File, expectedName: String, sidecarSuffixes: List<String>) {
        require(path.name == expectedName) { "Owned fixture name mismatch" }
        require(!Files.isSymbolicLink(path.toPath())) { "Owned fixture must not be a symbolic link" }
        require(path.canonicalFile.parentFile == parent.canonicalFile) { "Owned fixture escaped its directory" }
        val owned = ArrayList<File>()
        owned.add(path)
        for (suffix in sidecarSuffixes) owned.add(File(parent, expectedName + suffix))
        for (file in owned) {
            require(file.canonicalFile.parentFile == parent.canonicalFile) { "Owned fixture escaped its directory" }
            require(!Files.isSymbolicLink(file.toPath())) { "Owned fixture must not be a symbolic link" }
            if (!Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS)) continue
            require(!Files.isDirectory(file.toPath(), LinkOption.NOFOLLOW_LINKS)) { "Owned fixture must be a file" }
            if (!Files.deleteIfExists(file.toPath())) throw IOException("Owned fixture cleanup failed")
        }
    }

    /**
     * Deletes exactly the UUID-named capsule directory created by this test.
     * The name and canonical containment are checked before any traversal, and
     * symbolic links are never followed.
     */
    private fun deleteOwnedCapsuleTree(root: File, expectedName: String) {
        val id = expectedName.removePrefix("capsule-storage-")
        require(expectedName.startsWith("capsule-storage-") && UUID.fromString(id).toString() == id) {
            "Owned capsule directory name mismatch"
        }
        val owned = File(root, expectedName)
        require(!Files.isSymbolicLink(owned.toPath())) { "Owned capsule directory must not be a symbolic link" }
        val canonical = owned.canonicalFile
        require(canonical.parentFile == root.canonicalFile && canonical.name == expectedName) {
            "Owned capsule directory escaped its root"
        }
        if (!Files.exists(canonical.toPath(), LinkOption.NOFOLLOW_LINKS)) return
        require(Files.isDirectory(canonical.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            "Owned capsule directory is not a directory"
        }
        Files.walkFileTree(canonical.toPath(), object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                Files.delete(file)
                return FileVisitResult.CONTINUE
            }
            override fun postVisitDirectory(directory: Path, error: IOException?): FileVisitResult {
                if (error != null) throw error
                Files.delete(directory)
                return FileVisitResult.CONTINUE
            }
        })
    }
}

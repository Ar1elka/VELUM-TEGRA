package com.velumtegra.xuimobile.integration

import android.content.Context
import android.os.Process
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReplayScope
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 11.22 real-device proof that the production replay fence is anchored under the exact
 * Android app-private noBackupFilesDir and remains authoritative after an external am force-stop.
 *
 * The host runner deliberately kills the prepared target process. The fresh verification process
 * must reconstruct the production Application graph and still reject both exact consumed digests.
 * No SiteDeploymentCoordinator, transport, SSH/SFTP, credential, fixture server, or network path is
 * reachable from this test.
 */
@RunWith(AndroidJUnit4::class)
class Phase11_22RealDeviceDurableReplayForceStopAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun prepareConsumedMarkersAndAwaitExternalForceStop() {
        val nonce = requiredRunNonce()
        val permitSha = digest("phase11.22-runtime-permit:$nonce")
        val invocationSha = digest("phase11.22-coordinator-invocation:$nonce")
        readyMarker().delete()

        val noBackupRoot = context.noBackupFilesDir.canonicalFile
        val expectedReplayRoot = SiteProductionDeploymentAndroidReplayFence.canonicalRoot(context)
        assertEquals(noBackupRoot, expectedReplayRoot.parentFile)
        assertEquals(
            SiteProductionDeploymentAndroidReplayFence.ROOT_DIRECTORY_NAME,
            expectedReplayRoot.name,
        )

        val fence = application.siteProductionDeploymentReplayFence
        assertEquals(expectedReplayRoot.path, fence.snapshot().canonicalRootPath)
        assertTrue(fence.runtimeMutationConsumptionPort().consumeOnce(permitSha))
        assertTrue(fence.coordinatorInvocationUsePort().consumeOnce(invocationSha))
        assertTrue(fence.hasConsumed(SiteProductionDeploymentReplayScope.RUNTIME_MUTATION_PERMIT, permitSha))
        assertTrue(
            fence.hasConsumed(
                SiteProductionDeploymentReplayScope.COORDINATOR_INVOCATION_AUTHORIZATION,
                invocationSha,
            ),
        )

        writeReadyMarker(
            buildString {
                append("pid=").append(Process.myPid()).append('\n')
                append("nonce=").append(nonce).append('\n')
                append("permitSha256=").append(permitSha).append('\n')
                append("invocationSha256=").append(invocationSha).append('\n')
                append("replayRoot=").append(expectedReplayRoot.path).append('\n')
            },
        )

        // PASS for this preparation stage is the external host-side force-stop, never normal return.
        val deadline = System.nanoTime() + EXTERNAL_FORCE_STOP_WAIT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadline) {
            Thread.sleep(100L)
        }
        throw AssertionError("Phase 11.22 runner did not force-stop the prepared target process in time")
    }

    @Test
    fun verifyConsumedMarkersRemainNonReplayableAfterForceStop() {
        val nonce = requiredRunNonce()
        val marker = parseReadyMarker()
        assertEquals(nonce, marker.getValue("nonce"))

        val predecessorPid = marker.getValue("pid").toInt()
        assertNotEquals("Verification must run in a fresh process", predecessorPid, Process.myPid())

        val permitSha = digest("phase11.22-runtime-permit:$nonce")
        val invocationSha = digest("phase11.22-coordinator-invocation:$nonce")
        assertEquals(permitSha, marker.getValue("permitSha256"))
        assertEquals(invocationSha, marker.getValue("invocationSha256"))

        val noBackupRoot = context.noBackupFilesDir.canonicalFile
        val expectedReplayRoot = SiteProductionDeploymentAndroidReplayFence.canonicalRoot(context)
        assertEquals(noBackupRoot, expectedReplayRoot.parentFile)
        assertEquals(expectedReplayRoot.path, marker.getValue("replayRoot"))

        val reconstructedFence = application.siteProductionDeploymentReplayFence
        val snapshot = reconstructedFence.snapshot()
        assertEquals(expectedReplayRoot.path, snapshot.canonicalRootPath)
        assertTrue(
            reconstructedFence.hasConsumed(
                SiteProductionDeploymentReplayScope.RUNTIME_MUTATION_PERMIT,
                permitSha,
            ),
        )
        assertTrue(
            reconstructedFence.hasConsumed(
                SiteProductionDeploymentReplayScope.COORDINATOR_INVOCATION_AUTHORIZATION,
                invocationSha,
            ),
        )
        assertFalse(
            "Consumed runtime permit must remain non-replayable after force-stop/restart",
            reconstructedFence.runtimeMutationConsumptionPort().consumeOnce(permitSha),
        )
        assertFalse(
            "Consumed coordinator invocation authorization must remain non-replayable after force-stop/restart",
            reconstructedFence.coordinatorInvocationUsePort().consumeOnce(invocationSha),
        )
        assertTrue(snapshot.runtimeMutationPermitMarkerCount >= 1)
        assertTrue(snapshot.coordinatorInvocationAuthorizationMarkerCount >= 1)

        assertTrue("Ready marker cleanup failed", readyMarker().delete())
    }

    private fun requiredRunNonce(): String {
        val value = InstrumentationRegistry.getArguments().getString(ARG_RUN_NONCE)
            ?.trim()
            ?.lowercase()
            ?: throw AssertionError("Missing $ARG_RUN_NONCE instrumentation argument")
        require(RUN_NONCE.matches(value)) { "Phase 11.22 run nonce must be exactly 32 lowercase hex characters" }
        return value
    }

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun readyMarker(): File = File(context.filesDir, READY_MARKER_FILE)

    private fun writeReadyMarker(content: String) {
        FileOutputStream(readyMarker(), false).use { output ->
            output.write(content.encodeToByteArray())
            output.flush()
            output.fd.sync()
        }
    }

    private fun parseReadyMarker(): Map<String, String> {
        val file = readyMarker()
        assertTrue("Phase 11.22 ready marker is missing after process restart", file.isFile)
        return file.readLines()
            .mapNotNull { line ->
                val index = line.indexOf('=')
                if (index <= 0) null else line.substring(0, index) to line.substring(index + 1)
            }
            .toMap()
    }

    companion object {
        private const val ARG_RUN_NONCE = "phase11_22_run_nonce"
        private const val READY_MARKER_FILE = "phase11_22_site_replay_force_stop.marker"
        private const val EXTERNAL_FORCE_STOP_WAIT_MILLIS = 60_000L
        private val RUN_NONCE = Regex("^[0-9a-f]{32}$")
    }
}

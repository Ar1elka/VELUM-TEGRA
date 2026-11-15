package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentDurableReplayFencePhase1159BTest {
    @Test
    fun phase1159BProvisioningPlanIsDurablyConsumedExactlyOnce() {
        val root = Files.createTempDirectory("phase11-59b-replay-").toFile()
        val digest = "e".repeat(64)
        val first = SiteProductionDeploymentDurableReplayFence.open(root)
        assertTrue(first.realVpsWebServingRuntimeProvisioningExecutionUsePort().consumeOnce(digest))
        val restarted = SiteProductionDeploymentDurableReplayFence.open(root)
        assertFalse(restarted.realVpsWebServingRuntimeProvisioningExecutionUsePort().consumeOnce(digest))
        assertTrue(
            restarted.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_RUNTIME_PROVISIONING_EXECUTION_RECEIPT,
                digest,
            ),
        )
        assertEquals(1, restarted.snapshot().realVpsWebServingRuntimeProvisioningExecutionReceiptMarkerCount)
    }
}

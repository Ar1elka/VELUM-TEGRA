package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentDurableReplayFencePhase1160Test {
    @Test
    fun phase1160ActivationPlanIsDurablyConsumedExactlyOnce() {
        val root = Files.createTempDirectory("phase11-60-replay-").toFile()
        val digest = "f".repeat(64)
        val first = SiteProductionDeploymentDurableReplayFence.open(root)
        assertTrue(first.realVpsWebServingConfigActivationExecutionUsePort().consumeOnce(digest))
        val restarted = SiteProductionDeploymentDurableReplayFence.open(root)
        assertFalse(restarted.realVpsWebServingConfigActivationExecutionUsePort().consumeOnce(digest))
        assertTrue(
            restarted.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_CONFIG_ACTIVATION_EXECUTION_RECEIPT,
                digest,
            ),
        )
        assertEquals(1, restarted.snapshot().realVpsWebServingConfigActivationExecutionReceiptMarkerCount)
    }
}

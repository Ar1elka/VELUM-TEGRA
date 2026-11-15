package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentDurableReplayFencePhase1159Test {
    @Test
    fun phase1159ExecutionPlanIsDurablyConsumedExactlyOnce() {
        val root = Files.createTempDirectory("phase11-59-replay-").toFile()
        val digest = "d".repeat(64)
        val first = SiteProductionDeploymentDurableReplayFence.open(root)
        assertTrue(first.realVpsWebServingConfigStagingSyntaxExecutionUsePort().consumeOnce(digest))
        val restarted = SiteProductionDeploymentDurableReplayFence.open(root)
        assertFalse(restarted.realVpsWebServingConfigStagingSyntaxExecutionUsePort().consumeOnce(digest))
        assertTrue(
            restarted.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_CONFIG_STAGING_SYNTAX_EXECUTION_RECEIPT,
                digest,
            ),
        )
        assertEquals(1, restarted.snapshot().realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount)
    }
}

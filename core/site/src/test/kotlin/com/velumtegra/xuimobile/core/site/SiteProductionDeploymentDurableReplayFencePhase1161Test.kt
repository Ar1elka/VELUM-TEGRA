package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentDurableReplayFencePhase1161Test {
    @Test
    fun phase1161ReloadPlanIsDurablyConsumedExactlyOnce() {
        val root = Files.createTempDirectory("phase11-61-replay-").toFile()
        val digest = "6".repeat(64)
        val first = SiteProductionDeploymentDurableReplayFence.open(root)
        assertTrue(first.realVpsWebServingNginxReloadExecutionUsePort().consumeOnce(digest))
        val restarted = SiteProductionDeploymentDurableReplayFence.open(root)
        assertFalse(restarted.realVpsWebServingNginxReloadExecutionUsePort().consumeOnce(digest))
        assertTrue(
            restarted.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_NGINX_RELOAD_EXECUTION_RECEIPT,
                digest,
            ),
        )
        assertEquals(1, restarted.snapshot().realVpsWebServingNginxReloadExecutionReceiptMarkerCount)
    }
}

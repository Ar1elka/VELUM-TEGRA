package com.velumtegra.xuimobile.core.model

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ManagementModelTest {
    private val now = Instant.parse("2026-09-06T10:00:00Z")

    @Test
    fun rawMultilineTextCannotEnterNormalizedManagementObservation() {
        assertThrows(IllegalArgumentException::class.java) {
            ManagementObservation.ServiceUnitPresence(
                serviceUnit = "x-ui.service\nraw-output",
                presence = ManagementPresence.PRESENT,
                observedAt = now,
            )
        }
    }

    @Test
    fun panelSettingsRequireNormalizedPortAndAbsoluteBasePath() {
        assertThrows(IllegalArgumentException::class.java) {
            ManagementPanelSettings(70000, "/panel/", null)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ManagementPanelSettings(2053, "relative", null)
        }
        assertEquals("/panel/", ManagementPanelSettings(2053, "/panel/", null).webBasePath)
    }

    @Test
    fun managedMarkerPresenceCannotCarryAmbiguousNullState() {
        assertThrows(IllegalArgumentException::class.java) {
            ManagementObservation.ManagedInstallMarker(
                managedInstallId = null,
                presence = ManagementPresence.PRESENT,
                observedAt = now,
            )
        }
    }
}

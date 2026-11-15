package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagementBaselineDrift
import com.velumtegra.xuimobile.core.model.ManagementBaselineReadbackResult
import com.velumtegra.xuimobile.core.model.ManagementBaselineStatus
import com.velumtegra.xuimobile.core.model.ManagementEvidence
import com.velumtegra.xuimobile.core.model.ManagementEvidenceGap
import com.velumtegra.xuimobile.core.model.ManagementIdentityDrift
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ManagementObservation
import com.velumtegra.xuimobile.core.model.ManagementPanelSettings
import com.velumtegra.xuimobile.core.model.ManagementPathKind
import com.velumtegra.xuimobile.core.model.ManagementPresence
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Duration
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ManagementReadbackPolicyTest {
    private val now = Instant.parse("2026-09-06T10:00:10Z")
    private val observedAt = now.minusSeconds(2)
    private val identity = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui",
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = null,
    )
    private val baseline = InstallationBaseline(
        serviceUnit = identity.serviceUnit,
        binaryPath = identity.binaryPath,
        rootPath = identity.rootPath,
        databasePath = identity.databasePath,
        panelPort = 54321,
        webBasePath = "/panel/",
        listenAddress = "127.0.0.1",
        capturedAt = now.minusSeconds(60),
    )
    private val installation = XuiInstallation(
        id = XuiInstallationId("install-a"),
        serverId = ServerId("server-a"),
        ownership = InstallationOwnership.ADOPTED,
        identity = identity,
        baseline = baseline,
    )
    private val scope = ManagementScope(
        operationId = OperationId("quick-a"),
        serverId = installation.serverId,
        serverAccessId = ServerAccessId("access-a"),
        installationId = installation.id,
    )

    @Test
    fun quickInspectPlanIsFiniteTypedAndContainsNoCommandString() {
        val probes = ManagementProbePlan.quickInspect(installation)

        assertEquals(7, probes.size)
        assertTrue(probes.all { it.timeout == ManagementProbePlan.DEFAULT_PROBE_TIMEOUT })
        assertTrue(ManagementProbeSpec::class.java.declaredFields.none { it.name.contains("command", ignoreCase = true) })
    }

    @Test
    fun exactMatchingReadbackProducesFreshProofAndMatchedBaseline() {
        val result = ManagementReadbackPolicy.quickInspect(
            installation = installation,
            evidence = evidence(),
            proofId = TargetProofId("proof-a"),
            now = now,
        )

        assertEquals(ManagementIdentityStatus.Matched, result.identityStatus)
        assertEquals(ManagementServiceState.ACTIVE, result.serviceState)
        assertEquals(ManagementBaselineStatus.Matched, result.baselineStatus)
        assertNotNull(result.freshProof)
        assertEquals(scope.serverAccessId, result.freshProof?.serverAccessId)
        assertEquals(identity, result.freshProof?.observedIdentity)
    }

    @Test
    fun pathAbsenceIsTypedIdentityDriftAndBlocksFreshProof() {
        val observations = observations().map {
            if (it is ManagementObservation.PathPresence && it.pathKind == ManagementPathKind.DATABASE) {
                it.copy(presence = ManagementPresence.ABSENT)
            } else it
        }

        val result = ManagementReadbackPolicy.quickInspect(
            installation,
            ManagementEvidence(scope, observations),
            TargetProofId("proof-a"),
            now,
        )

        assertEquals(
            ManagementIdentityStatus.Drift(setOf(ManagementIdentityDrift.DATABASE_PATH_ABSENT)),
            result.identityStatus,
        )
        assertNull(result.freshProof)
    }

    @Test
    fun settingsAndListenerDriftNeverRewriteDurableBaseline() {
        val drifted = observations().mapNotNull {
            when (it) {
                is ManagementObservation.PanelSettings -> it.copy(
                    settings = ManagementPanelSettings(2053, "/changed/", "0.0.0.0"),
                )
                is ManagementObservation.ListenerPresence -> it.copy(presence = ManagementPresence.ABSENT)
                else -> it
            }
        }

        val result = ManagementReadbackPolicy.quickInspect(
            installation,
            ManagementEvidence(scope, drifted),
            TargetProofId("proof-a"),
            now,
        )

        assertEquals(
            ManagementBaselineStatus.Drift(
                setOf(
                    ManagementBaselineDrift.PANEL_PORT,
                    ManagementBaselineDrift.WEB_BASE_PATH,
                    ManagementBaselineDrift.LISTEN_ADDRESS,
                    ManagementBaselineDrift.EXPECTED_LISTENER_ABSENT,
                ),
            ),
            result.baselineStatus,
        )
        assertEquals(54321, installation.baseline.panelPort)
        assertEquals("/panel/", installation.baseline.webBasePath)
    }

    @Test
    fun missingSettingsIsInsufficientNotInventedBaseline() {
        val observations = observations().filterNot { it is ManagementObservation.PanelSettings }

        val result = ManagementReadbackPolicy.buildEnrollmentBaseline(
            identity,
            ManagementEvidence(scope, observations),
        )

        assertEquals(
            ManagementBaselineReadbackResult.Insufficient(setOf(ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED)),
            result,
        )
    }

    @Test
    fun enrollmentBaselineUsesOnlyNormalizedExactIdentityAndSettings() {
        val result = ManagementReadbackPolicy.buildEnrollmentBaseline(identity, evidence())

        val complete = result as ManagementBaselineReadbackResult.Complete
        assertEquals(identity.serviceUnit, complete.baseline.serviceUnit)
        assertEquals(identity.databasePath, complete.baseline.databasePath)
        assertEquals(54321, complete.baseline.panelPort)
        assertEquals("/panel/", complete.baseline.webBasePath)
    }

    @Test
    fun managedIdentityRequiresExplicitExactMarkerReadback() {
        val managedId = ManagedInstallId("managed-a")
        val managedIdentity = identity.copy(managedInstallId = managedId)
        val managedInstallation = installation.copy(
            ownership = InstallationOwnership.MANAGED,
            identity = managedIdentity,
        )
        val managedScope = scope.copy(installationId = managedInstallation.id)
        val noMarker = observations()

        val result = ManagementReadbackPolicy.quickInspect(
            managedInstallation,
            ManagementEvidence(managedScope, noMarker),
            TargetProofId("proof-managed"),
            now,
        )

        assertEquals(
            ManagementIdentityStatus.Insufficient(setOf(ManagementEvidenceGap.MANAGED_MARKER_UNOBSERVED)),
            result.identityStatus,
        )
        assertNull(result.freshProof)
    }

    @Test
    fun staleIdentityEvidenceDoesNotCreateFreshProof() {
        val stale = observations(now.minusSeconds(120))
        val result = ManagementReadbackPolicy.quickInspect(
            installation,
            ManagementEvidence(scope, stale),
            TargetProofId("proof-stale"),
            now,
            proofValidity = Duration.ofSeconds(30),
        )

        assertEquals(ManagementIdentityStatus.Matched, result.identityStatus)
        assertNull(result.freshProof)
    }

    @Test
    fun parsersRejectUnreviewedOrMalformedOutput() {
        assertEquals(
            ManagementProbeParseResult.Parsed(ManagementServiceState.ACTIVE),
            ManagementProbeParsers.parseServiceState("active\n"),
        )
        assertEquals(ManagementProbeParseResult.Malformed, ManagementProbeParsers.parseServiceState("active; rm -rf /"))
        assertEquals(
            ManagementProbeParseResult.Parsed(ManagementPresence.PRESENT),
            ManagementProbeParsers.parsePresenceExitCode(0),
        )
        assertEquals(ManagementProbeParseResult.Malformed, ManagementProbeParsers.parsePresenceExitCode(2))
        assertEquals(
            ManagementProbeParseResult.Parsed(ManagementPanelSettings(54321, "/panel/", "127.0.0.1")),
            ManagementProbeParsers.parsePanelSettings(
                "PORT=54321\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n",
            ),
        )
        assertEquals(
            ManagementProbeParseResult.Malformed,
            ManagementProbeParsers.parsePanelSettings("PORT=54321\nWEB_BASE_PATH=/panel/\nSHELL=oops\n"),
        )
    }

    private fun evidence(at: Instant = observedAt) = ManagementEvidence(scope, observations(at))

    private fun observations(at: Instant = observedAt): List<ManagementObservation> = listOf(
        ManagementObservation.ServiceUnitPresence(identity.serviceUnit, ManagementPresence.PRESENT, at),
        ManagementObservation.PathPresence(ManagementPathKind.BINARY, identity.binaryPath, ManagementPresence.PRESENT, at),
        ManagementObservation.PathPresence(ManagementPathKind.ROOT, identity.rootPath, ManagementPresence.PRESENT, at),
        ManagementObservation.PathPresence(ManagementPathKind.DATABASE, identity.databasePath, ManagementPresence.PRESENT, at),
        ManagementObservation.ServiceState(identity.serviceUnit, ManagementServiceState.ACTIVE, at.plusMillis(100)),
        ManagementObservation.PanelSettings(
            ManagementPanelSettings(54321, "/panel/", "127.0.0.1"),
            at.plusMillis(200),
        ),
        ManagementObservation.ListenerPresence(54321, "127.0.0.1", ManagementPresence.PRESENT, at.plusMillis(300)),
    )
}

package com.velumtegra.xuimobile.core.model

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DiscoveryModelTest {
    private val now = Instant.parse("2026-09-06T07:10:00Z")
    private val scope = DiscoveryScope(
        operationId = OperationId("discovery-op"),
        serverId = ServerId("server-a"),
        serverAccessId = ServerAccessId("access-a"),
    )
    private val identity = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui",
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = null,
    )

    @Test
    fun `discovery proof is structurally distinct from mutation installation proof`() {
        assertFalse(InstallationProof::class.java.isAssignableFrom(DiscoveryProof::class.java))
        assertFalse(DiscoveryProof::class.java.isAssignableFrom(InstallationProof::class.java))
        assertFalse(DiscoveryProof::class.java.declaredFields.any { it.name == "installationId" })
    }

    @Test(expected = IllegalArgumentException::class)
    fun `one weak signal cannot become discovery proof`() {
        DiscoveryProof(
            id = DiscoveryProofId("proof-a"),
            scope = scope,
            observedIdentity = identity,
            candidateBaseline = null,
            supportingSignals = setOf(DiscoveryProofSignal.SERVICE_UNIT),
            observedAt = now,
        )
    }

    @Test
    fun `two independent signals can form discovery proof without creating local installation id`() {
        val proof = DiscoveryProof(
            id = DiscoveryProofId("proof-a"),
            scope = scope,
            observedIdentity = identity,
            candidateBaseline = null,
            supportingSignals = setOf(
                DiscoveryProofSignal.SERVICE_UNIT,
                DiscoveryProofSignal.BINARY_PATH,
            ),
            observedAt = now,
        )

        assertEquals(scope, proof.scope)
        assertEquals(identity, proof.observedIdentity)
        assertNull(proof.candidateBaseline)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `managed identity requires explicit managed marker signal`() {
        DiscoveryProof(
            id = DiscoveryProofId("proof-managed"),
            scope = scope,
            observedIdentity = identity.copy(managedInstallId = ManagedInstallId("managed-a")),
            candidateBaseline = null,
            supportingSignals = setOf(
                DiscoveryProofSignal.SERVICE_UNIT,
                DiscoveryProofSignal.BINARY_PATH,
            ),
            observedAt = now,
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `candidate baseline cannot contradict proven installation identity`() {
        DiscoveryProof(
            id = DiscoveryProofId("proof-a"),
            scope = scope,
            observedIdentity = identity,
            candidateBaseline = InstallationBaseline(
                serviceUnit = "different.service",
                binaryPath = identity.binaryPath,
                rootPath = identity.rootPath,
                databasePath = identity.databasePath,
                panelPort = 2053,
                webBasePath = "/hidden/",
                listenAddress = "127.0.0.1",
                capturedAt = now,
            ),
            supportingSignals = setOf(
                DiscoveryProofSignal.SERVICE_UNIT,
                DiscoveryProofSignal.BINARY_PATH,
            ),
            observedAt = now,
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `normalized observation rejects multiline raw-like text`() {
        DiscoveryObservation.ServiceUnit(
            serviceUnit = "x-ui.service\nraw-shell-output",
            presence = DiscoveryPresence.PRESENT,
            observedAt = now,
        )
    }

    @Test
    fun `evidence carries exact operation server access scope only`() {
        val evidence = DiscoveryEvidence(
            scope = scope,
            observations = listOf(
                DiscoveryObservation.Platform(
                    platform = DiscoveryPlatform("ubuntu", "24.04"),
                    observedAt = now,
                ),
                DiscoveryObservation.ServiceUnit(
                    serviceUnit = "x-ui.service",
                    presence = DiscoveryPresence.PRESENT,
                    observedAt = now,
                ),
            ),
        )

        assertEquals(scope, evidence.scope)
        assertEquals(
            setOf(DiscoveryObservationKind.PLATFORM, DiscoveryObservationKind.SERVICE_UNIT),
            evidence.kinds,
        )
    }

    @Test
    fun `unsupported foreign ambiguous insufficient and transport failures remain distinct terminal results`() {
        val unsupported = DiscoveryResult.UnsupportedPlatform(
            scope = scope,
            platform = DiscoveryPlatform("debian", "13"),
            completedAt = now,
        )
        val foreign = DiscoveryResult.ForeignPanelDetected(scope, now)
        val ambiguous = DiscoveryResult.AmbiguousEvidence(
            scope,
            setOf(DiscoveryConflict.SUPPORTED_AND_FOREIGN_PANEL_EVIDENCE),
            now,
        )
        val insufficient = DiscoveryResult.InsufficientEvidence(
            scope,
            setOf(DiscoveryEvidenceGap.PERMISSION_DENIED),
            now,
        )
        val failed = DiscoveryResult.Failed(
            scope,
            DiscoveryFailureKind.AUTHENTICATION_REJECTED,
            now,
        )

        assertTrue(unsupported is DiscoveryResult.UnsupportedPlatform)
        assertTrue(foreign is DiscoveryResult.ForeignPanelDetected)
        assertTrue(ambiguous is DiscoveryResult.AmbiguousEvidence)
        assertTrue(insufficient is DiscoveryResult.InsufficientEvidence)
        assertEquals(DiscoveryFailureKind.AUTHENTICATION_REJECTED, failed.failure)
    }

    @Test
    fun `proven result derives exact scope from discovery proof`() {
        val proof = DiscoveryProof(
            id = DiscoveryProofId("proof-a"),
            scope = scope,
            observedIdentity = identity,
            candidateBaseline = null,
            supportingSignals = setOf(
                DiscoveryProofSignal.SERVICE_UNIT,
                DiscoveryProofSignal.BINARY_PATH,
            ),
            observedAt = now,
        )

        val result = DiscoveryResult.ProvenSupportedInstallation(proof, now.plusSeconds(1))

        assertEquals(scope, result.scope)
    }

    @Test
    fun `terminal kind is stable durable category for every discovery result variant`() {
        val proof = DiscoveryProof(
            id = DiscoveryProofId("proof-terminal-kind"),
            scope = scope,
            observedIdentity = identity,
            candidateBaseline = null,
            supportingSignals = setOf(
                DiscoveryProofSignal.SERVICE_UNIT,
                DiscoveryProofSignal.BINARY_PATH,
            ),
            observedAt = now,
        )
        val results = listOf(
            DiscoveryResult.ProvenSupportedInstallation(proof, now),
            DiscoveryResult.NoSupportedInstallation(scope, now),
            DiscoveryResult.UnsupportedPlatform(scope, DiscoveryPlatform("debian", "13"), now),
            DiscoveryResult.ForeignPanelDetected(scope, now),
            DiscoveryResult.AmbiguousEvidence(
                scope,
                setOf(DiscoveryConflict.SUPPORTED_AND_FOREIGN_PANEL_EVIDENCE),
                now,
            ),
            DiscoveryResult.InsufficientEvidence(
                scope,
                setOf(DiscoveryEvidenceGap.PERMISSION_DENIED),
                now,
            ),
            DiscoveryResult.Failed(scope, DiscoveryFailureKind.TRANSPORT_UNAVAILABLE, now),
            DiscoveryResult.Cancelled(scope, now),
        )
        val expected = listOf(
            DiscoveryTerminalKind.PROVEN_SUPPORTED,
            DiscoveryTerminalKind.NO_SUPPORTED_INSTALLATION,
            DiscoveryTerminalKind.UNSUPPORTED_PLATFORM,
            DiscoveryTerminalKind.FOREIGN_PANEL,
            DiscoveryTerminalKind.AMBIGUOUS,
            DiscoveryTerminalKind.INSUFFICIENT,
            DiscoveryTerminalKind.FAILED,
            DiscoveryTerminalKind.CANCELLED,
        )

        assertEquals(expected, results.map { it.terminalKind() })
        expected.forEach { kind ->
            assertEquals(kind, DiscoveryTerminalKind.fromPhaseName(kind.phaseName))
        }
        assertNull(DiscoveryTerminalKind.fromPhaseName("DISCOVERY_RESULT_UNKNOWN"))
    }

}

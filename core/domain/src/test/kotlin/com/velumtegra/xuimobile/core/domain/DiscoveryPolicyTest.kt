package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DiscoveryPolicyTest {
    private val now = Instant.parse("2026-09-06T07:30:00Z")
    private val scope = DiscoveryScope(
        operationId = OperationId("discovery-op"),
        serverId = ServerId("server-a"),
        serverAccessId = ServerAccessId("access-a"),
    )

    @Test
    fun `probe plan is finite typed and contains no raw command surface`() {
        assertTrue(DiscoveryProbePlan.initialProbes.isNotEmpty())
        assertTrue(DiscoveryProbePlan.initialProbes.size < 32)
        assertFalse(DiscoveryProbeSpec::class.java.declaredMethods.any { it.name.contains("command", ignoreCase = true) })
        assertTrue(DiscoveryProbePlan.initialProbes.all { !it.timeout.isZero && !it.timeout.isNegative })
    }

    @Test
    fun `os release parser normalizes Ubuntu and rejects conflicting duplicate id`() {
        val parsed = DiscoveryProbeParsers.parseOsRelease(
            "ID=Ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=ignored\n",
            now,
        )
        assertTrue(parsed is DiscoveryProbeParseResult.Parsed)
        val observation = (parsed as DiscoveryProbeParseResult.Parsed).value
        assertEquals(DiscoveryPlatform("ubuntu", "24.04"), observation.platform)

        val malformed = DiscoveryProbeParsers.parseOsRelease("ID=ubuntu\nID=debian\n", now)
        assertTrue(malformed is DiscoveryProbeParseResult.Malformed)
    }

    @Test
    fun `presence parser accepts only fixed predicate exit contract`() {
        assertEquals(
            DiscoveryPresence.PRESENT,
            (DiscoveryProbeParsers.parsePresenceExitCode(0) as DiscoveryProbeParseResult.Parsed).value,
        )
        assertEquals(
            DiscoveryPresence.ABSENT,
            (DiscoveryProbeParsers.parsePresenceExitCode(1) as DiscoveryProbeParseResult.Parsed).value,
        )
        assertTrue(DiscoveryProbeParsers.parsePresenceExitCode(2) is DiscoveryProbeParseResult.Malformed)
    }

    @Test
    fun `classification is independent of observation collection order`() {
        val observations = provenLayoutObservations()
        val forward = DiscoveryClassifier.classify(DiscoveryEvidence(scope, observations))
        val reverse = DiscoveryClassifier.classify(DiscoveryEvidence(scope, observations.reversed()))
        assertEquals(forward, reverse)
        assertTrue(forward is DiscoveryClassification.SupportedCandidate)
    }

    @Test
    fun `unsupported platform terminates before supported installation proof`() {
        val evidence = DiscoveryEvidence(
            scope,
            provenLayoutObservations().map {
                if (it is DiscoveryObservation.Platform) {
                    it.copy(platform = DiscoveryPlatform("alpine", "3.20"))
                } else it
            },
        )
        val classification = DiscoveryClassifier.classify(evidence)
        assertTrue(classification is DiscoveryClassification.UnsupportedPlatform)
        val attempt = DiscoveryProver.prove(evidence, classification, DiscoveryProofId("proof-a"))
        assertTrue(attempt is DiscoveryProofAttempt.NotApplicable)
    }

    @Test
    fun `supported and foreign panel evidence is ambiguous`() {
        val evidence = DiscoveryEvidence(
            scope,
            provenLayoutObservations() + DiscoveryObservation.PanelFamily(
                DiscoveryPanelFamily.SUPPORTED_3X_UI,
                now,
            ) + DiscoveryObservation.PanelFamily(
                DiscoveryPanelFamily.FOREIGN_PANEL,
                now,
            ),
        )
        val result = DiscoveryClassifier.classify(evidence)
        assertTrue(result is DiscoveryClassification.Ambiguous)
        assertTrue(
            DiscoveryConflict.SUPPORTED_AND_FOREIGN_PANEL_EVIDENCE in
                (result as DiscoveryClassification.Ambiguous).conflicts,
        )
    }

    @Test
    fun `contradictory presence evidence is ambiguous rather than latest wins`() {
        val evidence = DiscoveryEvidence(
            scope,
            listOf(
                platform(),
                service(DiscoveryPresence.PRESENT),
                service(DiscoveryPresence.ABSENT),
            ),
        )
        val result = DiscoveryClassifier.classify(evidence)
        assertTrue(result is DiscoveryClassification.Ambiguous)
        assertTrue(DiscoveryConflict.CONFLICTING_SERVICE_UNITS in (result as DiscoveryClassification.Ambiguous).conflicts)
    }

    @Test
    fun `complete explicit absence produces no supported installation`() {
        val observations = mutableListOf<DiscoveryObservation>(platform())
        DiscoveryProbePlan.supportedServiceUnits.forEach {
            observations += DiscoveryObservation.ServiceUnit(it, DiscoveryPresence.ABSENT, now)
        }
        DiscoveryProbePlan.supportedBinaryProbePaths.forEach {
            observations += DiscoveryObservation.InstallationPath(
                DiscoveryPathKind.BINARY,
                it,
                DiscoveryPresence.ABSENT,
                now,
            )
        }
        DiscoveryProbePlan.supportedDatabaseProbePaths.forEach {
            observations += DiscoveryObservation.InstallationPath(
                DiscoveryPathKind.DATABASE,
                it,
                DiscoveryPresence.ABSENT,
                now,
            )
        }
        val result = DiscoveryClassifier.classify(DiscoveryEvidence(scope, observations))
        assertTrue(result is DiscoveryClassification.NoSupportedInstallation)
    }

    @Test
    fun `partial negative evidence remains insufficient instead of guessing absence`() {
        val result = DiscoveryClassifier.classify(
            DiscoveryEvidence(scope, listOf(platform(), service(DiscoveryPresence.ABSENT))),
        )
        assertTrue(result is DiscoveryClassification.InsufficientEvidence)
    }

    @Test
    fun `canonical layout creates discovery proof without installation id`() {
        val evidence = DiscoveryEvidence(scope, provenLayoutObservations())
        val classification = DiscoveryClassifier.classify(evidence)
        val attempt = DiscoveryProver.prove(evidence, classification, DiscoveryProofId("proof-a"))
        assertTrue(attempt is DiscoveryProofAttempt.Proven)
        val proof = (attempt as DiscoveryProofAttempt.Proven).proof
        assertEquals("x-ui.service", proof.observedIdentity.serviceUnit)
        assertEquals("/usr/local/x-ui/x-ui", proof.observedIdentity.binaryPath)
        assertEquals("/usr/local/x-ui", proof.observedIdentity.rootPath)
        assertEquals("/etc/x-ui/x-ui.db", proof.observedIdentity.databasePath)
        assertNull(proof.observedIdentity.managedInstallId)
        assertTrue(proof.supportingSignals.containsAll(setOf(
            DiscoveryProofSignal.SERVICE_UNIT,
            DiscoveryProofSignal.BINARY_PATH,
            DiscoveryProofSignal.ROOT_PATH,
            DiscoveryProofSignal.DATABASE_PATH,
        )))
    }

    @Test
    fun `launcher path alone never infers root or becomes proven installation`() {
        val evidence = DiscoveryEvidence(
            scope,
            listOf(
                platform(),
                service(DiscoveryPresence.PRESENT),
                DiscoveryObservation.InstallationPath(
                    DiscoveryPathKind.BINARY,
                    "/usr/bin/x-ui",
                    DiscoveryPresence.PRESENT,
                    now,
                ),
                database(),
            ),
        )
        val classification = DiscoveryClassifier.classify(evidence)
        assertTrue(classification is DiscoveryClassification.SupportedCandidate)
        val attempt = DiscoveryProver.prove(evidence, classification, DiscoveryProofId("proof-a"))
        assertTrue(attempt is DiscoveryProofAttempt.InsufficientEvidence)
    }

    @Test
    fun `managed marker must be explicit and is carried only when observed`() {
        val managedId = ManagedInstallId("managed-a")
        val evidence = DiscoveryEvidence(
            scope,
            provenLayoutObservations() + DiscoveryObservation.ManagedInstallMarker(
                managedId,
                DiscoveryPresence.PRESENT,
                now.plusSeconds(1),
            ),
        )
        val classification = DiscoveryClassifier.classify(evidence)
        val proof = (DiscoveryProver.prove(
            evidence,
            classification,
            DiscoveryProofId("proof-managed"),
        ) as DiscoveryProofAttempt.Proven).proof
        assertEquals(managedId, proof.observedIdentity.managedInstallId)
        assertTrue(DiscoveryProofSignal.MANAGED_INSTALL_MARKER in proof.supportingSignals)
    }

    @Test
    fun `complete unique listener and web path produce optional baseline`() {
        val evidence = DiscoveryEvidence(
            scope,
            provenLayoutObservations() + listOf(
                DiscoveryObservation.Listener(2053, "127.0.0.1", now.plusSeconds(1)),
                DiscoveryObservation.WebBasePath("/hidden/", now.plusSeconds(2)),
            ),
        )
        val classification = DiscoveryClassifier.classify(evidence)
        val proof = (DiscoveryProver.prove(evidence, classification, DiscoveryProofId("proof-baseline"))
            as DiscoveryProofAttempt.Proven).proof
        assertEquals(2053, proof.candidateBaseline?.panelPort)
        assertEquals("/hidden/", proof.candidateBaseline?.webBasePath)
        assertTrue(DiscoveryProofSignal.PANEL_LISTENER in proof.supportingSignals)
        assertTrue(DiscoveryProofSignal.PANEL_SETTINGS in proof.supportingSignals)
    }

    @Test
    fun `conflicting optional baseline is omitted rather than guessed`() {
        val evidence = DiscoveryEvidence(
            scope,
            provenLayoutObservations() + listOf(
                DiscoveryObservation.Listener(2053, "127.0.0.1", now),
                DiscoveryObservation.Listener(8443, "127.0.0.1", now),
                DiscoveryObservation.WebBasePath("/hidden/", now),
            ),
        )
        val classification = DiscoveryClassifier.classify(evidence)
        val proof = (DiscoveryProver.prove(evidence, classification, DiscoveryProofId("proof-no-baseline"))
            as DiscoveryProofAttempt.Proven).proof
        assertNull(proof.candidateBaseline)
        assertFalse(DiscoveryProofSignal.PANEL_SETTINGS in proof.supportingSignals)
    }

    private fun platform() = DiscoveryObservation.Platform(
        DiscoveryPlatform("ubuntu", "24.04"),
        now,
    )

    private fun service(presence: DiscoveryPresence) = DiscoveryObservation.ServiceUnit(
        "x-ui.service",
        presence,
        now,
    )

    private fun database() = DiscoveryObservation.InstallationPath(
        DiscoveryPathKind.DATABASE,
        "/etc/x-ui/x-ui.db",
        DiscoveryPresence.PRESENT,
        now,
    )

    private fun provenLayoutObservations(): List<DiscoveryObservation> = listOf(
        platform(),
        service(DiscoveryPresence.PRESENT),
        DiscoveryObservation.InstallationPath(
            DiscoveryPathKind.BINARY,
            "/usr/local/x-ui/x-ui",
            DiscoveryPresence.PRESENT,
            now,
        ),
        DiscoveryObservation.InstallationPath(
            DiscoveryPathKind.ROOT,
            "/usr/local/x-ui",
            DiscoveryPresence.PRESENT,
            now,
        ),
        database(),
    )
}

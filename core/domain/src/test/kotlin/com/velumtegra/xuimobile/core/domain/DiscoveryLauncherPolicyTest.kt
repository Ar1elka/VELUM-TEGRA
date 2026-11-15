package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class DiscoveryLauncherPolicyTest {
    private val at = Instant.EPOCH
    private val scope = DiscoveryScope(OperationId("launcher"), ServerId("server"), ServerAccessId("access"))
    private fun path(kind: DiscoveryPathKind, value: String, presence: DiscoveryPresence = DiscoveryPresence.PRESENT) =
        DiscoveryObservation.InstallationPath(kind, value, presence, at)
    private fun launcher(value: String = "/usr/bin/x-ui", presence: DiscoveryPresence = DiscoveryPresence.PRESENT) =
        path(DiscoveryPathKind.BINARY, value, presence)
    private fun layout(): List<DiscoveryObservation> = listOf(
        DiscoveryObservation.Platform(DiscoveryPlatform("ubuntu", "24.04"), at),
        DiscoveryObservation.ServiceUnit("x-ui.service", DiscoveryPresence.PRESENT, at),
        path(DiscoveryPathKind.BINARY, "/usr/local/x-ui/x-ui"),
        path(DiscoveryPathKind.ROOT, "/usr/local/x-ui"),
        path(DiscoveryPathKind.DATABASE, "/etc/x-ui/x-ui.db"),
    )
    private fun evidence(o: List<DiscoveryObservation>) = DiscoveryEvidence(scope, o)
    private fun classify(o: List<DiscoveryObservation>) = DiscoveryClassifier.classify(evidence(o))
    private fun prove(o: List<DiscoveryObservation>) = DiscoveryProver.prove(evidence(o), classify(o), DiscoveryProofId("proof"))
    private fun assertConflict(o: List<DiscoveryObservation>) {
        val c = classify(o)
        assertTrue(c is DiscoveryClassification.Ambiguous)
        assertTrue(DiscoveryConflict.CONFLICTING_INSTALLATION_PATHS in (c as DiscoveryClassification.Ambiguous).conflicts)
        assertTrue(prove(o) is DiscoveryProofAttempt.NotApplicable)
    }

    @Test fun canonicalBinaryAndObservedCliLauncherProduceCanonicalProof() {
        val p = (prove(layout() + launcher()) as DiscoveryProofAttempt.Proven).proof
        assertEquals("/usr/local/x-ui/x-ui", p.observedIdentity.binaryPath)
        assertEquals("/etc/x-ui/x-ui.db", p.observedIdentity.databasePath)
        assertEquals(setOf(DiscoveryProofSignal.SERVICE_UNIT, DiscoveryProofSignal.BINARY_PATH,
            DiscoveryProofSignal.ROOT_PATH, DiscoveryProofSignal.DATABASE_PATH), p.supportingSignals)
    }
    @Test fun bothApprovedLaunchersRemainReportOnly() {
        assertTrue(prove(layout() + launcher() + launcher("/usr/local/bin/x-ui")) is DiscoveryProofAttempt.Proven)
        assertEquals(setOf("/usr/bin/x-ui", "/usr/local/bin/x-ui"), DiscoveryProbePlan.reportOnlyLauncherPaths)
        assertTrue(DiscoveryProbePlan.supportedLayouts.none { it.binaryPath in DiscoveryProbePlan.reportOnlyLauncherPaths })
    }
    @Test fun launcherOnlyCannotSupplyMissingCanonicalBinary() {
        val o = layout().filterNot { it is DiscoveryObservation.InstallationPath && it.pathKind == DiscoveryPathKind.BINARY } + launcher()
        assertTrue(classify(o) is DiscoveryClassification.SupportedCandidate)
        assertTrue(prove(o) is DiscoveryProofAttempt.InsufficientEvidence)
    }
    @Test fun twoCanonicalBinariesRemainConflictingWithLauncher() {
        assertConflict(layout() + launcher() + path(DiscoveryPathKind.BINARY, "/opt/x-ui/x-ui"))
    }
    @Test fun twoRootsRemainConflictingWithLauncher() {
        assertConflict(layout() + launcher() + path(DiscoveryPathKind.ROOT, "/opt/x-ui"))
    }
    @Test fun twoDatabasesRemainConflictingWithLauncher() {
        assertConflict(layout() + launcher() + path(DiscoveryPathKind.DATABASE, "/usr/local/x-ui/db/x-ui.db"))
    }
    @Test fun contradictoryLauncherPresenceStillFailsClosed() {
        assertConflict(layout() + launcher() + launcher(presence = DiscoveryPresence.ABSENT))
    }
    @Test fun contradictoryCanonicalPresenceStillFailsClosed() {
        assertConflict(layout() + launcher() + path(DiscoveryPathKind.BINARY, "/usr/local/x-ui/x-ui", DiscoveryPresence.ABSENT))
    }
    @Test fun unknownExecutablePathIsNotSilentlyDiscarded() {
        assertConflict(layout() + launcher() + path(DiscoveryPathKind.BINARY, "/unknown/x-ui"))
    }
    @Test fun launcherDoesNotRepairMismatchedLayout() {
        val o = layout().filterNot { it is DiscoveryObservation.InstallationPath && it.pathKind == DiscoveryPathKind.ROOT } +
            path(DiscoveryPathKind.ROOT, "/opt/x-ui") + launcher()
        assertTrue(prove(o) is DiscoveryProofAttempt.InsufficientEvidence)
    }
    @Test fun orderAndRepeatedPositiveLauncherDoNotChangeProofIdentity() {
        val o = layout() + launcher() + launcher()
        assertEquals(prove(o), prove(o.reversed()))
    }
    @Test fun oldAmbiguousClassificationCannotBeUsedToMintProof() {
        val o = layout() + launcher()
        val old = DiscoveryClassification.Ambiguous(setOf(DiscoveryConflict.CONFLICTING_INSTALLATION_PATHS))
        assertTrue(DiscoveryProver.prove(evidence(o), old, DiscoveryProofId("stale")) is DiscoveryProofAttempt.NotApplicable)
    }
    @Test fun missingServiceCannotBeInferredFromLauncher() {
        val o = layout().filterNot { it is DiscoveryObservation.ServiceUnit } + launcher()
        assertTrue(prove(o) is DiscoveryProofAttempt.InsufficientEvidence)
    }
    @Test fun alternateCanonicalLayoutKeepsItsOwnBinaryWithLaunchers() {
        val o = layout().map {
            if (it is DiscoveryObservation.InstallationPath && it.pathKind == DiscoveryPathKind.BINARY) {
                path(DiscoveryPathKind.BINARY, "/opt/x-ui/x-ui")
            } else if (it is DiscoveryObservation.InstallationPath && it.pathKind == DiscoveryPathKind.ROOT) {
                path(DiscoveryPathKind.ROOT, "/opt/x-ui")
            } else it
        } + launcher() + launcher("/usr/local/bin/x-ui")
        assertEquals("/opt/x-ui/x-ui", (prove(o) as DiscoveryProofAttempt.Proven).proof.observedIdentity.binaryPath)
    }
}

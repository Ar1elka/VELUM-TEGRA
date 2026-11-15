package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.DiscoveryClassification
import com.velumtegra.xuimobile.core.model.DiscoveryConflict
import com.velumtegra.xuimobile.core.model.DiscoveryEvidence
import com.velumtegra.xuimobile.core.model.DiscoveryEvidenceGap
import com.velumtegra.xuimobile.core.model.DiscoveryObservation
import com.velumtegra.xuimobile.core.model.DiscoveryPanelFamily
import com.velumtegra.xuimobile.core.model.DiscoveryPathKind
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.DiscoveryPresence
import com.velumtegra.xuimobile.core.model.DiscoveryProof
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryProofSignal
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import java.time.Instant
import java.util.Locale

/** Order-independent deterministic classification over normalized evidence. */
object DiscoveryClassifier {
    fun classify(evidence: DiscoveryEvidence): DiscoveryClassification {
        val observations = evidence.observations
        val platforms = observations.filterIsInstance<DiscoveryObservation.Platform>()
            .map { it.platform }
            .distinct()

        if (platforms.size > 1) {
            return DiscoveryClassification.Ambiguous(setOf(DiscoveryConflict.CONFLICTING_PLATFORM_EVIDENCE))
        }
        val platform = platforms.singleOrNull()
            ?: return DiscoveryClassification.InsufficientEvidence(setOf(DiscoveryEvidenceGap.PLATFORM_UNREADABLE))

        val conflicts = linkedSetOf<DiscoveryConflict>()
        collectPresenceConflicts(observations, conflicts)

        val presentServices = observations.filterIsInstance<DiscoveryObservation.ServiceUnit>()
            .filter { it.presence == DiscoveryPresence.PRESENT }
            .map { it.serviceUnit }
            .distinct()
        if (presentServices.size > 1) conflicts += DiscoveryConflict.CONFLICTING_SERVICE_UNITS

        DiscoveryPathKind.entries.forEach { kind ->
            val presentPaths = observations.filterIsInstance<DiscoveryObservation.InstallationPath>()
                .filter { it.pathKind == kind && it.presence == DiscoveryPresence.PRESENT }
                .filterNot {
                    kind == DiscoveryPathKind.BINARY && it.path in DiscoveryProbePlan.reportOnlyLauncherPaths
                }
                .map { it.path }
                .distinct()
            if (presentPaths.size > 1) conflicts += DiscoveryConflict.CONFLICTING_INSTALLATION_PATHS
        }

        val managedIds = observations.filterIsInstance<DiscoveryObservation.ManagedInstallMarker>()
            .filter { it.presence == DiscoveryPresence.PRESENT }
            .mapNotNull { it.managedInstallId }
            .distinct()
        if (managedIds.size > 1) conflicts += DiscoveryConflict.MULTIPLE_SUPPORTED_CANDIDATES

        val families = observations.filterIsInstance<DiscoveryObservation.PanelFamily>()
            .map { it.family }
            .toSet()
        if (DiscoveryPanelFamily.SUPPORTED_3X_UI in families && DiscoveryPanelFamily.FOREIGN_PANEL in families) {
            conflicts += DiscoveryConflict.SUPPORTED_AND_FOREIGN_PANEL_EVIDENCE
        }

        if (conflicts.isNotEmpty()) return DiscoveryClassification.Ambiguous(conflicts)

        if (!isSupportedUbuntu(platform)) {
            return DiscoveryClassification.UnsupportedPlatform(platform)
        }

        if (families == setOf(DiscoveryPanelFamily.FOREIGN_PANEL)) {
            return DiscoveryClassification.ForeignPanel
        }

        if (hasPositiveSupportedEvidence(observations, families)) {
            return DiscoveryClassification.SupportedCandidate(platform)
        }

        if (hasCompleteExplicitSupportedAbsence(observations)) {
            return DiscoveryClassification.NoSupportedInstallation
        }

        return DiscoveryClassification.InsufficientEvidence(
            setOf(DiscoveryEvidenceGap.INSTALLATION_IDENTITY_INCOMPLETE),
        )
    }

    /** The official 3x-ui installer and every apt-based step of this app support Ubuntu and Debian. */
    private fun isSupportedUbuntu(platform: DiscoveryPlatform): Boolean =
        platform.distributionId.lowercase(Locale.ROOT) in setOf("ubuntu", "debian")

    private fun hasPositiveSupportedEvidence(
        observations: List<DiscoveryObservation>,
        families: Set<DiscoveryPanelFamily>,
    ): Boolean {
        if (DiscoveryPanelFamily.SUPPORTED_3X_UI in families) return true

        val knownServicePresent = observations.filterIsInstance<DiscoveryObservation.ServiceUnit>()
            .any {
                it.presence == DiscoveryPresence.PRESENT &&
                    it.serviceUnit in DiscoveryProbePlan.supportedServiceUnits
            }
        if (knownServicePresent) return true

        return observations.filterIsInstance<DiscoveryObservation.InstallationPath>().any { observation ->
            if (observation.presence != DiscoveryPresence.PRESENT) return@any false
            when (observation.pathKind) {
                DiscoveryPathKind.BINARY -> observation.path in DiscoveryProbePlan.supportedBinaryProbePaths
                DiscoveryPathKind.DATABASE -> observation.path in DiscoveryProbePlan.supportedDatabaseProbePaths
                DiscoveryPathKind.ROOT -> false // a stale directory alone is intentionally not enough
            }
        }
    }

    private fun hasCompleteExplicitSupportedAbsence(observations: List<DiscoveryObservation>): Boolean {
        fun serviceAbsent(unit: String): Boolean = observations
            .filterIsInstance<DiscoveryObservation.ServiceUnit>()
            .any { it.serviceUnit == unit && it.presence == DiscoveryPresence.ABSENT }

        fun pathAbsent(kind: DiscoveryPathKind, path: String): Boolean = observations
            .filterIsInstance<DiscoveryObservation.InstallationPath>()
            .any { it.pathKind == kind && it.path == path && it.presence == DiscoveryPresence.ABSENT }

        return DiscoveryProbePlan.supportedServiceUnits.all(::serviceAbsent) &&
            DiscoveryProbePlan.supportedBinaryProbePaths.all { pathAbsent(DiscoveryPathKind.BINARY, it) } &&
            DiscoveryProbePlan.supportedDatabaseProbePaths.all { pathAbsent(DiscoveryPathKind.DATABASE, it) }
    }

    private fun collectPresenceConflicts(
        observations: List<DiscoveryObservation>,
        conflicts: MutableSet<DiscoveryConflict>,
    ) {
        observations.filterIsInstance<DiscoveryObservation.ServiceUnit>()
            .groupBy { it.serviceUnit }
            .values
            .filter { group -> group.map { it.presence }.toSet().size > 1 }
            .forEach { conflicts += DiscoveryConflict.CONFLICTING_SERVICE_UNITS }

        observations.filterIsInstance<DiscoveryObservation.InstallationPath>()
            .groupBy { it.pathKind to it.path }
            .values
            .filter { group -> group.map { it.presence }.toSet().size > 1 }
            .forEach { conflicts += DiscoveryConflict.CONFLICTING_INSTALLATION_PATHS }
    }
}

sealed interface DiscoveryProofAttempt {
    data class Proven(val proof: DiscoveryProof) : DiscoveryProofAttempt
    data class InsufficientEvidence(val gaps: Set<DiscoveryEvidenceGap>) : DiscoveryProofAttempt
    data class NotApplicable(val classification: DiscoveryClassification) : DiscoveryProofAttempt
}

/** Strict approved proof combinations. No path is inferred from another path. */
object DiscoveryProver {
    fun prove(
        evidence: DiscoveryEvidence,
        classification: DiscoveryClassification,
        proofId: DiscoveryProofId,
    ): DiscoveryProofAttempt {
        val currentClassification = DiscoveryClassifier.classify(evidence)
        if (currentClassification != classification) {
            return DiscoveryProofAttempt.NotApplicable(currentClassification)
        }
        if (currentClassification !is DiscoveryClassification.SupportedCandidate) {
            return DiscoveryProofAttempt.NotApplicable(currentClassification)
        }

        val observations = evidence.observations
        val service = uniquePresentService(observations)
        val binary = uniquePresentPath(observations, DiscoveryPathKind.BINARY)
        val root = uniquePresentPath(observations, DiscoveryPathKind.ROOT)
        val database = uniquePresentPath(observations, DiscoveryPathKind.DATABASE)

        val layout = DiscoveryProbePlan.supportedLayouts.singleOrNull { candidate ->
            candidate.binaryPath == binary &&
                candidate.rootPath == root &&
                database != null && database in candidate.databasePaths
        }

        if (service == null || service !in DiscoveryProbePlan.supportedServiceUnits || layout == null) {
            return DiscoveryProofAttempt.InsufficientEvidence(
                setOf(DiscoveryEvidenceGap.INSTALLATION_IDENTITY_INCOMPLETE),
            )
        }

        val managedMarker = observations.filterIsInstance<DiscoveryObservation.ManagedInstallMarker>()
            .filter { it.presence == DiscoveryPresence.PRESENT }
            .mapNotNull { it.managedInstallId }
            .distinct()
            .singleOrNull()

        val identityObservations = observations.filter { observation ->
            when (observation) {
                is DiscoveryObservation.ServiceUnit ->
                    observation.presence == DiscoveryPresence.PRESENT && observation.serviceUnit == service
                is DiscoveryObservation.InstallationPath ->
                    observation.presence == DiscoveryPresence.PRESENT && observation.path in setOf(binary, root, database)
                is DiscoveryObservation.ManagedInstallMarker ->
                    managedMarker != null && observation.managedInstallId == managedMarker &&
                        observation.presence == DiscoveryPresence.PRESENT
                else -> false
            }
        }
        val observedAt = identityObservations.maxOf { it.observedAt }

        val identity = InstallationIdentity(
            serviceUnit = service,
            binaryPath = requireNotNull(binary),
            rootPath = requireNotNull(root),
            databasePath = requireNotNull(database),
            managedInstallId = managedMarker,
        )

        val signals = linkedSetOf(
            DiscoveryProofSignal.SERVICE_UNIT,
            DiscoveryProofSignal.BINARY_PATH,
            DiscoveryProofSignal.ROOT_PATH,
            DiscoveryProofSignal.DATABASE_PATH,
        )
        if (managedMarker != null) signals += DiscoveryProofSignal.MANAGED_INSTALL_MARKER

        val baseline = buildOptionalBaseline(observations, identity, observedAt)
        if (baseline != null) {
            signals += DiscoveryProofSignal.PANEL_LISTENER
            signals += DiscoveryProofSignal.PANEL_SETTINGS
        }

        val proofObservedAt = maxOf(observedAt, baseline?.capturedAt ?: observedAt)
        return DiscoveryProofAttempt.Proven(
            DiscoveryProof(
                id = proofId,
                scope = evidence.scope,
                observedIdentity = identity,
                candidateBaseline = baseline,
                supportingSignals = signals,
                observedAt = proofObservedAt,
            ),
        )
    }

    private fun uniquePresentService(observations: List<DiscoveryObservation>): String? = observations
        .filterIsInstance<DiscoveryObservation.ServiceUnit>()
        .filter { it.presence == DiscoveryPresence.PRESENT }
        .map { it.serviceUnit }
        .distinct()
        .singleOrNull()

    private fun uniquePresentPath(
        observations: List<DiscoveryObservation>,
        kind: DiscoveryPathKind,
    ): String? = observations
        .filterIsInstance<DiscoveryObservation.InstallationPath>()
        .filter { it.pathKind == kind && it.presence == DiscoveryPresence.PRESENT }
        .filterNot {
            kind == DiscoveryPathKind.BINARY && it.path in DiscoveryProbePlan.reportOnlyLauncherPaths
        }
        .map { it.path }
        .distinct()
        .singleOrNull()

    private fun buildOptionalBaseline(
        observations: List<DiscoveryObservation>,
        identity: InstallationIdentity,
        identityObservedAt: Instant,
    ): InstallationBaseline? {
        val listeners = observations.filterIsInstance<DiscoveryObservation.Listener>()
            .distinctBy { it.port to it.listenAddress }
        val webPaths = observations.filterIsInstance<DiscoveryObservation.WebBasePath>()
            .distinctBy { it.webBasePath }
        if (listeners.size != 1 || webPaths.size != 1) return null

        val listener = listeners.single()
        val webPath = webPaths.single()
        val capturedAt = maxOf(identityObservedAt, listener.observedAt, webPath.observedAt)
        return InstallationBaseline(
            serviceUnit = identity.serviceUnit,
            binaryPath = identity.binaryPath,
            rootPath = identity.rootPath,
            databasePath = identity.databasePath,
            panelPort = listener.port,
            webBasePath = webPath.webBasePath,
            listenAddress = listener.listenAddress,
            capturedAt = capturedAt,
        )
    }
}

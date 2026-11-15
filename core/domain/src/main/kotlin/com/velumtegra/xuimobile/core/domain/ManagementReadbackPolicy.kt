package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationProof
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagementBaselineDrift
import com.velumtegra.xuimobile.core.model.ManagementBaselineReadbackResult
import com.velumtegra.xuimobile.core.model.ManagementBaselineStatus
import com.velumtegra.xuimobile.core.model.ManagementEvidence
import com.velumtegra.xuimobile.core.model.ManagementEvidenceGap
import com.velumtegra.xuimobile.core.model.ManagementIdentityDrift
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot
import com.velumtegra.xuimobile.core.model.ManagementObservation
import com.velumtegra.xuimobile.core.model.ManagementPanelSettings
import com.velumtegra.xuimobile.core.model.ManagementPathKind
import com.velumtegra.xuimobile.core.model.ManagementPresence
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Locale

/** Typed, reviewed Management read-back vocabulary. No free-form command string exists here. */
sealed interface ManagementProbeSpec {
    val timeout: Duration

    data class ServiceUnitPresence(
        val serviceUnit: String,
        override val timeout: Duration = ManagementProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : ManagementProbeSpec

    data class ServiceLiveState(
        val serviceUnit: String,
        override val timeout: Duration = ManagementProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : ManagementProbeSpec

    data class ExactPathPresence(
        val pathKind: ManagementPathKind,
        val path: String,
        override val timeout: Duration = ManagementProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : ManagementProbeSpec

    /** Optional for ADOPTED; mandatory for proving a MANAGED identity. Concrete source is reviewed in 6.4. */
    data class ManagedInstallMarkerReadback(
        val expectedManagedInstallId: ManagedInstallId,
        override val timeout: Duration = ManagementProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : ManagementProbeSpec

    /** Targeted settings read-back from the exact already-proven database path; never a broad SQLite inventory. */
    data class PanelSettingsReadback(
        val exactDatabasePath: String,
        override val timeout: Duration = ManagementProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : ManagementProbeSpec

    data class ExactListenerPresence(
        val expectedPort: Int,
        val expectedListenAddress: String?,
        override val timeout: Duration = ManagementProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : ManagementProbeSpec
}

object ManagementProbePlan {
    val DEFAULT_PROBE_TIMEOUT: Duration = Duration.ofSeconds(5)
    val DEFAULT_PROOF_VALIDITY: Duration = Duration.ofSeconds(30)

    fun enrollmentBaseline(identity: InstallationIdentity): List<ManagementProbeSpec> = buildList {
        addIdentityProbes(identity)
        add(ManagementProbeSpec.PanelSettingsReadback(identity.databasePath))
    }

    fun quickInspect(installation: XuiInstallation): List<ManagementProbeSpec> = buildList {
        addIdentityProbes(installation.identity)
        add(ManagementProbeSpec.ServiceLiveState(installation.identity.serviceUnit))
        add(ManagementProbeSpec.PanelSettingsReadback(installation.identity.databasePath))
        add(
            ManagementProbeSpec.ExactListenerPresence(
                expectedPort = installation.baseline.panelPort,
                expectedListenAddress = installation.baseline.listenAddress,
            ),
        )
    }

    private fun MutableList<ManagementProbeSpec>.addIdentityProbes(identity: InstallationIdentity) {
        add(ManagementProbeSpec.ServiceUnitPresence(identity.serviceUnit))
        add(ManagementProbeSpec.ExactPathPresence(ManagementPathKind.BINARY, identity.binaryPath))
        add(ManagementProbeSpec.ExactPathPresence(ManagementPathKind.ROOT, identity.rootPath))
        add(ManagementProbeSpec.ExactPathPresence(ManagementPathKind.DATABASE, identity.databasePath))
        identity.managedInstallId?.let { add(ManagementProbeSpec.ManagedInstallMarkerReadback(it)) }
    }
}

sealed interface ManagementProbeParseResult<out T> {
    data class Parsed<T>(val value: T) : ManagementProbeParseResult<T>
    data object Malformed : ManagementProbeParseResult<Nothing>
}

/** Strict parsers for transient output emitted by reviewed 6.4 command forms. */
object ManagementProbeParsers {
    private const val MAX_SERVICE_STATE_BYTES = 64
    private const val MAX_SETTINGS_BYTES = 1024
    private const val MAX_SETTINGS_LINES = 8

    fun parsePresenceExitCode(exitCode: Int): ManagementProbeParseResult<ManagementPresence> = when (exitCode) {
        0 -> ManagementProbeParseResult.Parsed(ManagementPresence.PRESENT)
        1 -> ManagementProbeParseResult.Parsed(ManagementPresence.ABSENT)
        else -> ManagementProbeParseResult.Malformed
    }

    fun parseServiceState(raw: String): ManagementProbeParseResult<ManagementServiceState> {
        if (raw.toByteArray(StandardCharsets.UTF_8).size > MAX_SERVICE_STATE_BYTES) {
            return ManagementProbeParseResult.Malformed
        }
        val token = raw.trim().lowercase(Locale.ROOT)
        val state = when (token) {
            "active" -> ManagementServiceState.ACTIVE
            "inactive" -> ManagementServiceState.INACTIVE
            "failed" -> ManagementServiceState.FAILED
            "activating" -> ManagementServiceState.ACTIVATING
            "deactivating" -> ManagementServiceState.DEACTIVATING
            "reloading" -> ManagementServiceState.RELOADING
            "unknown" -> ManagementServiceState.UNKNOWN
            else -> return ManagementProbeParseResult.Malformed
        }
        return ManagementProbeParseResult.Parsed(state)
    }

    /**
     * Reviewed settings command must emit exactly these normalized keys:
     * PORT=<1..65535>, WEB_BASE_PATH=</...>, LISTEN_ADDRESS=<text or empty>.
     */
    fun parsePanelSettings(raw: String): ManagementProbeParseResult<ManagementPanelSettings> {
        if (raw.toByteArray(StandardCharsets.UTF_8).size > MAX_SETTINGS_BYTES || '\u0000' in raw) {
            return ManagementProbeParseResult.Malformed
        }
        val lines = raw.lineSequence().filter { it.isNotBlank() }.toList()
        if (lines.size !in 2..MAX_SETTINGS_LINES) return ManagementProbeParseResult.Malformed

        val values = linkedMapOf<String, String>()
        for (line in lines) {
            val index = line.indexOf('=')
            if (index <= 0) return ManagementProbeParseResult.Malformed
            val key = line.substring(0, index)
            val value = line.substring(index + 1)
            if (key !in setOf("PORT", "WEB_BASE_PATH", "LISTEN_ADDRESS")) {
                return ManagementProbeParseResult.Malformed
            }
            if (values.put(key, value) != null) return ManagementProbeParseResult.Malformed
        }

        val port = values["PORT"]?.toIntOrNull() ?: return ManagementProbeParseResult.Malformed
        val webBasePath = values["WEB_BASE_PATH"] ?: return ManagementProbeParseResult.Malformed
        val listenAddress = values["LISTEN_ADDRESS"]?.takeIf { it.isNotEmpty() }
        return try {
            ManagementProbeParseResult.Parsed(
                ManagementPanelSettings(
                    panelPort = port,
                    webBasePath = webBasePath,
                    listenAddress = listenAddress,
                ),
            )
        } catch (_: IllegalArgumentException) {
            ManagementProbeParseResult.Malformed
        }
    }
}

object ManagementReadbackPolicy {
    fun buildEnrollmentBaseline(
        expectedIdentity: InstallationIdentity,
        evidence: ManagementEvidence,
    ): ManagementBaselineReadbackResult {
        val identity = evaluateIdentity(expectedIdentity, evidence.observations)
        when (identity) {
            is ManagementIdentityStatus.Drift -> return ManagementBaselineReadbackResult.IdentityDrift(identity.fields)
            is ManagementIdentityStatus.Insufficient -> return ManagementBaselineReadbackResult.Insufficient(identity.gaps)
            ManagementIdentityStatus.Matched -> Unit
        }

        val settings = uniquePanelSettings(evidence.observations)
            ?: return ManagementBaselineReadbackResult.Insufficient(settingsGap(evidence.observations))
        val observedAt = evidence.observations.maxOf { it.observedAt }
        return ManagementBaselineReadbackResult.Complete(
            InstallationBaseline(
                serviceUnit = expectedIdentity.serviceUnit,
                binaryPath = expectedIdentity.binaryPath,
                rootPath = expectedIdentity.rootPath,
                databasePath = expectedIdentity.databasePath,
                panelPort = settings.settings.panelPort,
                webBasePath = settings.settings.webBasePath,
                listenAddress = settings.settings.listenAddress,
                capturedAt = maxOf(observedAt, settings.observedAt),
            ),
        )
    }

    fun quickInspect(
        installation: XuiInstallation,
        evidence: ManagementEvidence,
        proofId: TargetProofId,
        now: Instant,
        proofValidity: Duration = ManagementProbePlan.DEFAULT_PROOF_VALIDITY,
    ): ManagementLiveSnapshot {
        require(!proofValidity.isNegative && !proofValidity.isZero) { "proofValidity must be positive" }
        require(evidence.scope.serverId == installation.serverId) { "Evidence belongs to another server" }
        require(evidence.scope.installationId == installation.id) { "Evidence belongs to another installation" }

        val identityStatus = evaluateIdentity(installation.identity, evidence.observations)
        val serviceState = uniqueServiceState(installation.identity.serviceUnit, evidence.observations)
            ?: ManagementServiceState.UNKNOWN
        val baselineStatus = evaluateBaseline(installation.baseline, evidence.observations)
        val observedAt = evidence.observations.maxOf { it.observedAt }

        val proof = if (identityStatus == ManagementIdentityStatus.Matched) {
            val identityObservedAt = identityObservedAt(installation.identity, evidence.observations)
            val validUntil = identityObservedAt?.plus(proofValidity)
            if (identityObservedAt != null && validUntil != null && !now.isAfter(validUntil)) {
                InstallationProof(
                    id = proofId,
                    installationId = installation.id,
                    serverId = installation.serverId,
                    serverAccessId = evidence.scope.serverAccessId,
                    observedIdentity = installation.identity,
                    observedAt = identityObservedAt,
                    validUntil = validUntil,
                )
            } else {
                null
            }
        } else {
            null
        }

        return ManagementLiveSnapshot(
            scope = evidence.scope,
            identityStatus = identityStatus,
            serviceState = serviceState,
            baselineStatus = baselineStatus,
            freshProof = proof,
            observedAt = observedAt,
        )
    }

    private fun evaluateIdentity(
        expected: InstallationIdentity,
        observations: List<ManagementObservation>,
    ): ManagementIdentityStatus {
        val gaps = linkedSetOf<ManagementEvidenceGap>()
        val drift = linkedSetOf<ManagementIdentityDrift>()

        evaluatePresence(
            observations.filterIsInstance<ManagementObservation.ServiceUnitPresence>()
                .filter { it.serviceUnit == expected.serviceUnit }
                .map { it.presence },
            ManagementEvidenceGap.SERVICE_UNIT_UNOBSERVED,
            ManagementIdentityDrift.SERVICE_UNIT_ABSENT,
            gaps,
            drift,
        )
        evaluatePath(expected.binaryPath, ManagementPathKind.BINARY, observations,
            ManagementEvidenceGap.BINARY_PATH_UNOBSERVED, ManagementIdentityDrift.BINARY_PATH_ABSENT, gaps, drift)
        evaluatePath(expected.rootPath, ManagementPathKind.ROOT, observations,
            ManagementEvidenceGap.ROOT_PATH_UNOBSERVED, ManagementIdentityDrift.ROOT_PATH_ABSENT, gaps, drift)
        evaluatePath(expected.databasePath, ManagementPathKind.DATABASE, observations,
            ManagementEvidenceGap.DATABASE_PATH_UNOBSERVED, ManagementIdentityDrift.DATABASE_PATH_ABSENT, gaps, drift)

        expected.managedInstallId?.let { expectedMarker ->
            val markers = observations.filterIsInstance<ManagementObservation.ManagedInstallMarker>()
            if (markers.isEmpty()) {
                gaps += ManagementEvidenceGap.MANAGED_MARKER_UNOBSERVED
            } else {
                val presentIds = markers.filter { it.presence == ManagementPresence.PRESENT }
                    .mapNotNull { it.managedInstallId }
                    .distinct()
                val absent = markers.any { it.presence == ManagementPresence.ABSENT }
                when {
                    presentIds.size > 1 || (presentIds.isNotEmpty() && absent) -> gaps += ManagementEvidenceGap.CONFLICTING_EVIDENCE
                    absent -> drift += ManagementIdentityDrift.MANAGED_MARKER_ABSENT
                    presentIds.singleOrNull() != expectedMarker -> drift += ManagementIdentityDrift.MANAGED_MARKER_MISMATCH
                }
            }
        }

        return when {
            drift.isNotEmpty() -> ManagementIdentityStatus.Drift(drift)
            gaps.isNotEmpty() -> ManagementIdentityStatus.Insufficient(gaps)
            else -> ManagementIdentityStatus.Matched
        }
    }

    private fun evaluateBaseline(
        baseline: InstallationBaseline,
        observations: List<ManagementObservation>,
    ): ManagementBaselineStatus {
        val settingsObservations = observations.filterIsInstance<ManagementObservation.PanelSettings>()
        val listenerObservations = observations.filterIsInstance<ManagementObservation.ListenerPresence>()
            .filter { it.port == baseline.panelPort && it.listenAddress == baseline.listenAddress }

        val gaps = linkedSetOf<ManagementEvidenceGap>()
        val drift = linkedSetOf<ManagementBaselineDrift>()

        val distinctSettings = settingsObservations.map { it.settings }.distinct()
        if (distinctSettings.size > 1) {
            gaps += ManagementEvidenceGap.CONFLICTING_EVIDENCE
        } else if (distinctSettings.isEmpty()) {
            gaps += ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED
        } else {
            val live = distinctSettings.single()
            if (live.panelPort != baseline.panelPort) drift += ManagementBaselineDrift.PANEL_PORT
            if (live.webBasePath != baseline.webBasePath) drift += ManagementBaselineDrift.WEB_BASE_PATH
            if (live.listenAddress != baseline.listenAddress) drift += ManagementBaselineDrift.LISTEN_ADDRESS
        }

        val listenerPresence = listenerObservations.map { it.presence }.distinct()
        when {
            listenerPresence.size > 1 -> gaps += ManagementEvidenceGap.CONFLICTING_EVIDENCE
            listenerPresence.isEmpty() -> gaps += ManagementEvidenceGap.LISTENER_UNOBSERVED
            listenerPresence.single() == ManagementPresence.ABSENT -> drift += ManagementBaselineDrift.EXPECTED_LISTENER_ABSENT
        }

        return when {
            drift.isNotEmpty() -> ManagementBaselineStatus.Drift(drift)
            gaps.isNotEmpty() -> ManagementBaselineStatus.Insufficient(gaps)
            else -> ManagementBaselineStatus.Matched
        }
    }

    private fun evaluatePath(
        expectedPath: String,
        kind: ManagementPathKind,
        observations: List<ManagementObservation>,
        gap: ManagementEvidenceGap,
        absentDrift: ManagementIdentityDrift,
        gaps: MutableSet<ManagementEvidenceGap>,
        drift: MutableSet<ManagementIdentityDrift>,
    ) {
        val values = observations.filterIsInstance<ManagementObservation.PathPresence>()
            .filter { it.pathKind == kind && it.path == expectedPath }
            .map { it.presence }
        evaluatePresence(values, gap, absentDrift, gaps, drift)
    }

    private fun evaluatePresence(
        values: List<ManagementPresence>,
        gap: ManagementEvidenceGap,
        absentDrift: ManagementIdentityDrift,
        gaps: MutableSet<ManagementEvidenceGap>,
        drift: MutableSet<ManagementIdentityDrift>,
    ) {
        val distinct = values.distinct()
        when {
            distinct.size > 1 -> gaps += ManagementEvidenceGap.CONFLICTING_EVIDENCE
            distinct.isEmpty() -> gaps += gap
            distinct.single() == ManagementPresence.ABSENT -> drift += absentDrift
        }
    }

    private fun uniquePanelSettings(observations: List<ManagementObservation>): ManagementObservation.PanelSettings? {
        val settings = observations.filterIsInstance<ManagementObservation.PanelSettings>()
        return if (settings.map { it.settings }.distinct().size == 1) settings.maxByOrNull { it.observedAt } else null
    }

    private fun settingsGap(observations: List<ManagementObservation>): Set<ManagementEvidenceGap> {
        val count = observations.filterIsInstance<ManagementObservation.PanelSettings>()
            .map { it.settings }
            .distinct()
            .size
        return if (count > 1) setOf(ManagementEvidenceGap.CONFLICTING_EVIDENCE)
        else setOf(ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED)
    }

    private fun uniqueServiceState(
        serviceUnit: String,
        observations: List<ManagementObservation>,
    ): ManagementServiceState? {
        val states = observations.filterIsInstance<ManagementObservation.ServiceState>()
            .filter { it.serviceUnit == serviceUnit }
            .map { it.state }
            .distinct()
        return states.singleOrNull()
    }

    private fun identityObservedAt(
        expected: InstallationIdentity,
        observations: List<ManagementObservation>,
    ): Instant? {
        val relevant = observations.filter { observation ->
            when (observation) {
                is ManagementObservation.ServiceUnitPresence -> observation.serviceUnit == expected.serviceUnit
                is ManagementObservation.PathPresence -> when (observation.pathKind) {
                    ManagementPathKind.BINARY -> observation.path == expected.binaryPath
                    ManagementPathKind.ROOT -> observation.path == expected.rootPath
                    ManagementPathKind.DATABASE -> observation.path == expected.databasePath
                }
                is ManagementObservation.ManagedInstallMarker -> expected.managedInstallId != null
                else -> false
            }
        }
        return relevant.maxOfOrNull { it.observedAt }
    }
}

package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.DeepDiagnosticBinaryVersionStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticCertificateReferences
import com.velumtegra.xuimobile.core.model.DeepDiagnosticDatabaseIntegrityStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticDatabaseSchemaStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticEvidence
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFilePresence
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFinding
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFindingCode
import com.velumtegra.xuimobile.core.model.DeepDiagnosticObservation
import com.velumtegra.xuimobile.core.model.DeepDiagnosticOverallStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticScope
import com.velumtegra.xuimobile.core.model.DeepDiagnosticServiceDefinitionStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticSeverity
import com.velumtegra.xuimobile.core.model.DeepDiagnosticSnapshot
import com.velumtegra.xuimobile.core.model.ManagementBaselineStatus
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.time.Duration
import java.time.Instant

/** Deep-specific typed probes. No raw shell or arbitrary filesystem query can be supplied by a caller. */
sealed interface DeepDiagnosticProbeSpec {
    val timeout: Duration

    data class ServiceDefinitionReadback(
        val serviceUnit: String,
        val expectedBinaryPath: String,
        override val timeout: Duration = DeepDiagnosticProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DeepDiagnosticProbeSpec {
        init {
            requireDeepProbeText(serviceUnit, "serviceUnit", 255)
            requireDeepProbePath(expectedBinaryPath, "expectedBinaryPath")
            requireDeepProbeTimeout(timeout)
        }
    }

    data class BinaryVersionReadback(
        val binaryPath: String,
        override val timeout: Duration = DeepDiagnosticProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DeepDiagnosticProbeSpec {
        init {
            requireDeepProbePath(binaryPath, "binaryPath")
            requireDeepProbeTimeout(timeout)
        }
    }

    data class DatabaseQuickCheck(
        val databasePath: String,
        override val timeout: Duration = DeepDiagnosticProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DeepDiagnosticProbeSpec {
        init {
            requireDeepProbePath(databasePath, "databasePath")
            requireDeepProbeTimeout(timeout)
        }
    }

    data class DatabaseSchemaReadback(
        val databasePath: String,
        override val timeout: Duration = DeepDiagnosticProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DeepDiagnosticProbeSpec {
        init {
            requireDeepProbePath(databasePath, "databasePath")
            requireDeepProbeTimeout(timeout)
        }
    }

    /** Reads only certificate/key references from the exact already-known database. */
    data class CertificateReferencesReadback(
        val databasePath: String,
        override val timeout: Duration = DeepDiagnosticProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DeepDiagnosticProbeSpec {
        init {
            requireDeepProbePath(databasePath, "databasePath")
            requireDeepProbeTimeout(timeout)
        }
    }

    /** Derived only from a validated absolute certificate path returned by CertificateReferencesReadback. */
    data class ExactCertificateFileReadback(
        val certificatePath: String,
        override val timeout: Duration = DeepDiagnosticProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DeepDiagnosticProbeSpec {
        init {
            requireDeepProbePath(certificatePath, "certificatePath")
            requireDeepProbeTimeout(timeout)
        }
    }

    /** Presence/metadata only; private-key contents must never be read. */
    data class ExactPrivateKeyPresence(
        val privateKeyPath: String,
        override val timeout: Duration = DeepDiagnosticProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DeepDiagnosticProbeSpec {
        init {
            requireDeepProbePath(privateKeyPath, "privateKeyPath")
            requireDeepProbeTimeout(timeout)
        }
    }
}

data class DeepDiagnosticProbePlan(
    val managementPrelude: List<ManagementProbeSpec>,
    val primaryProbes: List<DeepDiagnosticProbeSpec>,
) {
    init {
        require(managementPrelude.isNotEmpty())
        require(primaryProbes.isNotEmpty())
        require(managementPrelude.size + primaryProbes.size <= MAX_PRIMARY_TOTAL_PROBES)
    }

    companion object {
        val DEFAULT_PROBE_TIMEOUT: Duration = Duration.ofSeconds(10)
        const val MAX_PRIMARY_TOTAL_PROBES: Int = 13
        const val MAX_DERIVED_RESOURCE_PROBES: Int = 2

        fun forInstallation(installation: XuiInstallation): DeepDiagnosticProbePlan = DeepDiagnosticProbePlan(
            managementPrelude = ManagementProbePlan.quickInspect(installation),
            primaryProbes = listOf(
                DeepDiagnosticProbeSpec.ServiceDefinitionReadback(
                    serviceUnit = installation.identity.serviceUnit,
                    expectedBinaryPath = installation.identity.binaryPath,
                ),
                DeepDiagnosticProbeSpec.BinaryVersionReadback(installation.identity.binaryPath),
                DeepDiagnosticProbeSpec.DatabaseQuickCheck(installation.identity.databasePath),
                DeepDiagnosticProbeSpec.DatabaseSchemaReadback(installation.identity.databasePath),
                DeepDiagnosticProbeSpec.CertificateReferencesReadback(installation.identity.databasePath),
            ),
        )

        fun derivedCertificateProbes(references: DeepDiagnosticCertificateReferences): List<DeepDiagnosticProbeSpec> = buildList {
            references.certificatePath?.let { add(DeepDiagnosticProbeSpec.ExactCertificateFileReadback(it)) }
            references.privateKeyPath?.let { add(DeepDiagnosticProbeSpec.ExactPrivateKeyPresence(it)) }
        }.also { require(it.size <= MAX_DERIVED_RESOURCE_PROBES) }
    }
}

private fun requireDeepProbeTimeout(timeout: Duration) {
    require(!timeout.isZero && !timeout.isNegative && timeout <= Duration.ofSeconds(30)) {
        "Deep Diagnostic probe timeout must be in (0, 30s]"
    }
}

private fun requireDeepProbeText(value: String, field: String, maxLength: Int) {
    require(value.isNotBlank()) { "$field must not be blank" }
    require(value.length <= maxLength) { "$field is too long" }
    require(value.none { it == '\u0000' || it == '\n' || it == '\r' }) { "$field contains control characters" }
}

private fun requireDeepProbePath(value: String, field: String) {
    requireDeepProbeText(value, field, 1024)
    require(value.startsWith('/')) { "$field must be absolute" }
    require(!value.contains("//")) { "$field must be normalized" }
    require(value.split('/').none { it == "." || it == ".." }) { "$field must not contain dot segments" }
}

object DeepDiagnosticPolicy {
    fun evaluate(
        scope: DeepDiagnosticScope,
        managementSnapshot: ManagementLiveSnapshot,
        evidence: DeepDiagnosticEvidence,
        now: Instant,
    ): DeepDiagnosticSnapshot {
        require(evidence.scope == scope) { "Deep Diagnostic evidence belongs to another scope" }
        require(managementSnapshot.scope.operationId == scope.operationId)
        require(managementSnapshot.scope.serverId == scope.serverId)
        require(managementSnapshot.scope.serverAccessId == scope.serverAccessId)
        require(managementSnapshot.scope.installationId == scope.installationId)

        val findings = linkedSetOf<DeepDiagnosticFinding>()

        when (managementSnapshot.identityStatus) {
            ManagementIdentityStatus.Matched -> Unit
            is ManagementIdentityStatus.Drift -> findings += critical(DeepDiagnosticFindingCode.IDENTITY_DRIFT)
            is ManagementIdentityStatus.Insufficient -> findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
        }

        if (managementSnapshot.serviceState != ManagementServiceState.ACTIVE) {
            findings += warning(DeepDiagnosticFindingCode.SERVICE_NOT_ACTIVE)
        }

        when (managementSnapshot.baselineStatus) {
            ManagementBaselineStatus.Matched -> Unit
            is ManagementBaselineStatus.Drift -> findings += warning(DeepDiagnosticFindingCode.BASELINE_DRIFT)
            is ManagementBaselineStatus.Insufficient -> findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
        }

        val serviceDefinition = unique<DeepDiagnosticObservation.ServiceDefinition>(evidence.observations)
        when (serviceDefinition?.status) {
            DeepDiagnosticServiceDefinitionStatus.CONSISTENT -> Unit
            DeepDiagnosticServiceDefinitionStatus.UNIT_MISSING,
            DeepDiagnosticServiceDefinitionStatus.EXEC_START_MISMATCH -> findings += critical(DeepDiagnosticFindingCode.SERVICE_DEFINITION_DRIFT)
            DeepDiagnosticServiceDefinitionStatus.UNREADABLE,
            null -> findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
        }

        val binaryVersion = unique<DeepDiagnosticObservation.BinaryVersion>(evidence.observations)
        if (binaryVersion == null) {
            findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
        } else if (binaryVersion.status == DeepDiagnosticBinaryVersionStatus.UNAVAILABLE) {
            findings += info(DeepDiagnosticFindingCode.BINARY_VERSION_UNAVAILABLE)
        }

        when (unique<DeepDiagnosticObservation.DatabaseIntegrity>(evidence.observations)?.status) {
            DeepDiagnosticDatabaseIntegrityStatus.OK -> Unit
            DeepDiagnosticDatabaseIntegrityStatus.FAILED -> findings += critical(DeepDiagnosticFindingCode.DATABASE_INTEGRITY_FAILED)
            DeepDiagnosticDatabaseIntegrityStatus.UNREADABLE,
            null -> findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
        }

        when (unique<DeepDiagnosticObservation.DatabaseSchema>(evidence.observations)?.status) {
            DeepDiagnosticDatabaseSchemaStatus.SUPPORTED -> Unit
            DeepDiagnosticDatabaseSchemaStatus.INCOMPLETE -> findings += critical(DeepDiagnosticFindingCode.DATABASE_SCHEMA_INCOMPLETE)
            DeepDiagnosticDatabaseSchemaStatus.UNREADABLE,
            null -> findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
        }

        evaluateCertificates(evidence.observations, now, findings)

        val overall = when {
            findings.any { it.severity == DeepDiagnosticSeverity.CRITICAL } -> DeepDiagnosticOverallStatus.CRITICAL
            findings.any { it.code == DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE } -> DeepDiagnosticOverallStatus.INSUFFICIENT
            findings.any { it.severity == DeepDiagnosticSeverity.WARNING } -> DeepDiagnosticOverallStatus.DEGRADED
            else -> DeepDiagnosticOverallStatus.HEALTHY
        }

        val observedAt = maxOf(managementSnapshot.observedAt, evidence.observations.maxOf { it.observedAt })
        return DeepDiagnosticSnapshot(
            scope = scope,
            managementSnapshot = managementSnapshot,
            findings = findings,
            overallStatus = overall,
            observedAt = observedAt,
        )
    }

    private fun evaluateCertificates(
        observations: List<DeepDiagnosticObservation>,
        now: Instant,
        findings: MutableSet<DeepDiagnosticFinding>,
    ) {
        val referencesObservation = unique<DeepDiagnosticObservation.CertificateReferences>(observations)
        if (referencesObservation == null) {
            findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
            return
        }
        val references = referencesObservation.references
        if (!references.isConfigured) return

        references.certificatePath?.let { path ->
            val certificate = observations.filterIsInstance<DeepDiagnosticObservation.CertificateFile>()
                .singleOrNull { it.path == path }
            when (certificate?.presence) {
                DeepDiagnosticFilePresence.PRESENT -> {
                    certificate.notAfter?.let { if (it.isBefore(now)) findings += critical(DeepDiagnosticFindingCode.CERTIFICATE_EXPIRED) }
                    certificate.notBefore?.let { if (it.isAfter(now)) findings += warning(DeepDiagnosticFindingCode.CERTIFICATE_NOT_YET_VALID) }
                }
                DeepDiagnosticFilePresence.ABSENT -> findings += critical(DeepDiagnosticFindingCode.CERTIFICATE_MISSING)
                DeepDiagnosticFilePresence.UNREADABLE,
                null -> findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
            }
        }

        references.privateKeyPath?.let { path ->
            val key = observations.filterIsInstance<DeepDiagnosticObservation.PrivateKeyFile>()
                .singleOrNull { it.path == path }
            when (key?.presence) {
                DeepDiagnosticFilePresence.PRESENT -> Unit
                DeepDiagnosticFilePresence.ABSENT -> findings += critical(DeepDiagnosticFindingCode.PRIVATE_KEY_MISSING)
                DeepDiagnosticFilePresence.UNREADABLE,
                null -> findings += warning(DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE)
            }
        }
    }

    private inline fun <reified T : DeepDiagnosticObservation> unique(observations: List<DeepDiagnosticObservation>): T? {
        val matches = observations.filterIsInstance<T>()
        return if (matches.size == 1) matches.single() else null
    }

    private fun info(code: DeepDiagnosticFindingCode) = DeepDiagnosticFinding(code, DeepDiagnosticSeverity.INFO)
    private fun warning(code: DeepDiagnosticFindingCode) = DeepDiagnosticFinding(code, DeepDiagnosticSeverity.WARNING)
    private fun critical(code: DeepDiagnosticFindingCode) = DeepDiagnosticFinding(code, DeepDiagnosticSeverity.CRITICAL)
}

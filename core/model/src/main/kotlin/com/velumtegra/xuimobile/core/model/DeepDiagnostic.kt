package com.velumtegra.xuimobile.core.model

import java.time.Instant

/** Exact immutable identity of one explicit DEEP_DIAGNOSTIC operation. */
data class DeepDiagnosticScope(
    val operationId: OperationId,
    val serverId: ServerId,
    val serverAccessId: ServerAccessId,
    val installationId: XuiInstallationId,
)

enum class DeepDiagnosticServiceDefinitionStatus {
    CONSISTENT,
    UNIT_MISSING,
    EXEC_START_MISMATCH,
    UNREADABLE,
}

enum class DeepDiagnosticBinaryVersionStatus {
    AVAILABLE,
    UNAVAILABLE,
}

enum class DeepDiagnosticDatabaseIntegrityStatus {
    OK,
    FAILED,
    UNREADABLE,
}

enum class DeepDiagnosticDatabaseSchemaStatus {
    SUPPORTED,
    INCOMPLETE,
    UNREADABLE,
}

enum class DeepDiagnosticFilePresence {
    PRESENT,
    ABSENT,
    UNREADABLE,
}

data class DeepDiagnosticCertificateReferences(
    val certificatePath: String?,
    val privateKeyPath: String?,
) {
    init {
        certificatePath?.let { requireDeepDiagnosticPath(it, "certificatePath") }
        privateKeyPath?.let { requireDeepDiagnosticPath(it, "privateKeyPath") }
    }

    val isConfigured: Boolean
        get() = certificatePath != null || privateKeyPath != null
}

/** Safe normalized Deep Diagnostic fact. Raw command/stdout/stderr is intentionally not representable. */
sealed interface DeepDiagnosticObservation {
    val observedAt: Instant

    data class ServiceDefinition(
        val serviceUnit: String,
        val expectedBinaryPath: String,
        val status: DeepDiagnosticServiceDefinitionStatus,
        override val observedAt: Instant,
    ) : DeepDiagnosticObservation {
        init {
            requireDeepDiagnosticText(serviceUnit, "serviceUnit", 255)
            requireDeepDiagnosticPath(expectedBinaryPath, "expectedBinaryPath")
        }
    }

    data class BinaryVersion(
        val binaryPath: String,
        val status: DeepDiagnosticBinaryVersionStatus,
        val normalizedVersion: String?,
        override val observedAt: Instant,
    ) : DeepDiagnosticObservation {
        init {
            requireDeepDiagnosticPath(binaryPath, "binaryPath")
            when (status) {
                DeepDiagnosticBinaryVersionStatus.AVAILABLE -> {
                    val version = requireNotNull(normalizedVersion) { "Available binary version requires normalizedVersion" }
                    requireDeepDiagnosticText(version, "normalizedVersion", 128)
                }
                DeepDiagnosticBinaryVersionStatus.UNAVAILABLE -> require(normalizedVersion == null) {
                    "Unavailable binary version cannot carry normalizedVersion"
                }
            }
        }
    }

    data class DatabaseIntegrity(
        val databasePath: String,
        val status: DeepDiagnosticDatabaseIntegrityStatus,
        override val observedAt: Instant,
    ) : DeepDiagnosticObservation {
        init { requireDeepDiagnosticPath(databasePath, "databasePath") }
    }

    data class DatabaseSchema(
        val databasePath: String,
        val status: DeepDiagnosticDatabaseSchemaStatus,
        override val observedAt: Instant,
    ) : DeepDiagnosticObservation {
        init { requireDeepDiagnosticPath(databasePath, "databasePath") }
    }

    data class CertificateReferences(
        val databasePath: String,
        val references: DeepDiagnosticCertificateReferences,
        override val observedAt: Instant,
    ) : DeepDiagnosticObservation {
        init { requireDeepDiagnosticPath(databasePath, "databasePath") }
    }

    data class CertificateFile(
        val path: String,
        val presence: DeepDiagnosticFilePresence,
        val notBefore: Instant?,
        val notAfter: Instant?,
        override val observedAt: Instant,
    ) : DeepDiagnosticObservation {
        init {
            requireDeepDiagnosticPath(path, "certificate path")
            if (presence != DeepDiagnosticFilePresence.PRESENT) {
                require(notBefore == null && notAfter == null) {
                    "Absent/unreadable certificate cannot carry validity timestamps"
                }
            }
            if (notBefore != null && notAfter != null) require(!notAfter.isBefore(notBefore)) {
                "Certificate notAfter cannot precede notBefore"
            }
        }
    }

    /** Presence only. Private-key bytes are never read into the diagnostic model. */
    data class PrivateKeyFile(
        val path: String,
        val presence: DeepDiagnosticFilePresence,
        override val observedAt: Instant,
    ) : DeepDiagnosticObservation {
        init { requireDeepDiagnosticPath(path, "private key path") }
    }
}

data class DeepDiagnosticEvidence(
    val scope: DeepDiagnosticScope,
    val observations: List<DeepDiagnosticObservation>,
) {
    init { require(observations.isNotEmpty()) { "Deep Diagnostic evidence must not be empty" } }
}

enum class DeepDiagnosticSeverity {
    INFO,
    WARNING,
    CRITICAL,
}

enum class DeepDiagnosticFindingCode {
    IDENTITY_DRIFT,
    SERVICE_NOT_ACTIVE,
    BASELINE_DRIFT,
    SERVICE_DEFINITION_DRIFT,
    BINARY_VERSION_UNAVAILABLE,
    DATABASE_INTEGRITY_FAILED,
    DATABASE_SCHEMA_INCOMPLETE,
    CERTIFICATE_MISSING,
    PRIVATE_KEY_MISSING,
    CERTIFICATE_EXPIRED,
    CERTIFICATE_NOT_YET_VALID,
    INSUFFICIENT_EVIDENCE,
}

data class DeepDiagnosticFinding(
    val code: DeepDiagnosticFindingCode,
    val severity: DeepDiagnosticSeverity,
)

enum class DeepDiagnosticOverallStatus {
    HEALTHY,
    DEGRADED,
    CRITICAL,
    INSUFFICIENT,
}

/** Process-local Deep Diagnostic result. It is not a durable baseline mutation. */
data class DeepDiagnosticSnapshot(
    val scope: DeepDiagnosticScope,
    val managementSnapshot: ManagementLiveSnapshot,
    val findings: Set<DeepDiagnosticFinding>,
    val overallStatus: DeepDiagnosticOverallStatus,
    val observedAt: Instant,
) {
    init {
        require(managementSnapshot.scope.operationId == scope.operationId)
        require(managementSnapshot.scope.serverId == scope.serverId)
        require(managementSnapshot.scope.serverAccessId == scope.serverAccessId)
        require(managementSnapshot.scope.installationId == scope.installationId)
        require(!managementSnapshot.observedAt.isAfter(observedAt))
    }
}

private fun requireDeepDiagnosticText(value: String, field: String, maxLength: Int) {
    require(value.isNotBlank()) { "$field must not be blank" }
    require(value.length <= maxLength) { "$field is too long" }
    require(value.none { it == '\u0000' || it == '\n' || it == '\r' }) { "$field contains control characters" }
}

private fun requireDeepDiagnosticPath(value: String, field: String) {
    requireDeepDiagnosticText(value, field, 1024)
    require(value.startsWith('/')) { "$field must be absolute" }
    require(!value.contains("//")) { "$field must be normalized" }
    require(value.split('/').none { it == "." || it == ".." }) { "$field must not contain dot segments" }
}

package com.velumtegra.xuimobile.core.model

import java.time.Duration
import java.time.Instant

enum class ExistingInstallationRecoveryDiagnosis {
    HEALTHY,
    EXACT_SERVICE_INACTIVE_LISTENER_ABSENT,
    UNSUPPORTED_OR_CONTRADICTED,
    INCOMPLETE,
}

enum class ExistingInstallationRecoveryCapability {
    SYSTEMD_START_EXACT_SERVICE_V1,
}

data class ExistingInstallationRecoveryEvidence(
    val scope: ExistingInstallationActionScope,
    val diagnosis: ExistingInstallationRecoveryDiagnosis,
    val serviceState: ManagementServiceState,
    val observedAt: Instant,
    val validUntil: Instant,
) {
    init {
        require(scope.action == OperationType.RECOVERY) { "Recovery evidence requires RECOVERY scope" }
        require(!validUntil.isBefore(observedAt)) { "Recovery evidence validity cannot end before observation" }
    }
}

data class ReviewedExistingInstallationRecoveryRepairPlan(
    val scope: ExistingInstallationActionScope,
    val capability: ExistingInstallationRecoveryCapability,
    val timeout: Duration,
) {
    init {
        require(scope.action == OperationType.RECOVERY) { "Recovery repair plan requires RECOVERY scope" }
        require(!timeout.isZero && !timeout.isNegative) { "Recovery repair timeout must be positive" }
    }
}

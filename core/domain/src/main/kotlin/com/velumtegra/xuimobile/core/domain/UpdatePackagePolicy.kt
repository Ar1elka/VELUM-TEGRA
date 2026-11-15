package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Duration
import java.time.Instant

enum class UpdatePackageBlocker { PRECHECKS, STALE_REPORT, UNKNOWN_ARCHITECTURE, UNSUPPORTED_VERSION, NO_NEWER_REVIEWED_RELEASE }
sealed interface UpdatePackageEligibility {
    data class Available(val release: ReviewedXuiUpdatePackage) : UpdatePackageEligibility
    data class Blocked(val reason: UpdatePackageBlocker) : UpdatePackageEligibility
}

/** Package selection is local and cannot authorize an upgrade, restart or restore. */
object UpdatePackagePolicy {
    val REPORT_VALIDITY: Duration = Duration.ofMinutes(10)
    val recoveryRequirements: List<UpdateRecoveryRequirement> = UpdateRecoveryRequirement.entries.toList()

    fun review(report: UpdatePreflightSnapshot, now: Instant): UpdatePackageEligibility {
        if (listOf(report.scope.operationId.value, report.scope.serverId.value,
                report.scope.installationId.value, report.scope.serverAccessId.value).any { it.isBlank() } ||
            UpdatePreparationPolicy.blockingChecks(report).isNotEmpty())
            return UpdatePackageEligibility.Blocked(UpdatePackageBlocker.PRECHECKS)
        if (now.isBefore(report.observedAt) || Duration.between(report.observedAt, now) > REPORT_VALIDITY)
            return UpdatePackageEligibility.Blocked(UpdatePackageBlocker.STALE_REPORT)
        val architecture = report.architecture
            ?: return UpdatePackageEligibility.Blocked(UpdatePackageBlocker.UNKNOWN_ARCHITECTURE)
        val current = stableVersion(report.currentVersion)
            ?: return UpdatePackageEligibility.Blocked(UpdatePackageBlocker.UNSUPPORTED_VERSION)
        val release = ReviewedXuiUpdatePackage.entries.single { it.architecture == architecture }
        val target = requireNotNull(stableVersion(release.version))
        val firstDifference = current.zip(target).firstOrNull { it.first != it.second }
        if (firstDifference == null || firstDifference.first > firstDifference.second)
            return UpdatePackageEligibility.Blocked(UpdatePackageBlocker.NO_NEWER_REVIEWED_RELEASE)
        return UpdatePackageEligibility.Available(release)
    }

    fun matches(request: UpdatePackageRequest, now: Instant): Boolean =
        (review(request.report, now) as? UpdatePackageEligibility.Available)?.release == request.release

    fun receiptMatches(request: UpdatePackageRequest, receipt: UpdatePackageReceipt, now: Instant): Boolean =
        matches(request, now) && receipt.scope == request.report.scope &&
            receipt.preflightObservedAt == request.report.observedAt && receipt.release == request.release &&
            receipt.sha256 == request.release.sha256 && receipt.sizeBytes in 1..UpdatePackageReceipt.MAX_BYTES &&
            !receipt.verifiedAt.isBefore(request.report.observedAt) && !receipt.verifiedAt.isAfter(now)

    private fun stableVersion(value: String?): List<Int>? {
        if (value == null || !Regex("v?[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}").matches(value)) return null
        return value.removePrefix("v").split('.').map { it.toInt() }
    }
}

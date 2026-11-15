package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Duration
import java.time.Instant

enum class UpdateRecoveryBlocker {
    SOURCE_NOT_OBSERVED, STALE_OR_FUTURE_REPORT, EXACT_TARGET_MISSING, CURRENT_INSTALLATION,
    ARCHITECTURE_UNSUPPORTED, STABLE_VERSION_REQUIRED, REQUIRED_TOOLS,
    DATABASE_ACCESS, DATABASE_CHANGED, DATABASE_INTEGRITY, DATABASE_SCHEMA, RUNTIME_FILES, PANEL_TLS,
}

sealed interface UpdateRecoveryPlanReview {
    data class Draft(val plan: UpdateRecoveryDraftPlan) : UpdateRecoveryPlanReview
    data class Blocked(val reasons: Set<UpdateRecoveryBlocker>) : UpdateRecoveryPlanReview
}

/** Source checks admit a reviewable draft only, not a consistent copy or tested recovery claim. */
object UpdateRecoveryReadinessPolicy {
    val MAX_AGE: Duration = Duration.ofMinutes(5)

    fun review(report: UpdatePreflightSnapshot, now: Instant): UpdateRecoveryPlanReview {
        val source = report.recovery
        val blockers = linkedSetOf<UpdateRecoveryBlocker>()
        val scope = report.scope
        if (listOf(scope.operationId.value, scope.serverId.value, scope.serverAccessId.value, scope.installationId.value)
                .any { it.isBlank() }) blockers += UpdateRecoveryBlocker.EXACT_TARGET_MISSING
        if (report.observedAt.isAfter(now) || Duration.between(report.observedAt, now) >= MAX_AGE)
            blockers += UpdateRecoveryBlocker.STALE_OR_FUTURE_REPORT
        if (UpdatePreparationPolicy.blockingChecks(report).isNotEmpty()) blockers += UpdateRecoveryBlocker.CURRENT_INSTALLATION
        if (report.architecture == null) blockers += UpdateRecoveryBlocker.ARCHITECTURE_UNSUPPORTED
        if (report.currentVersion?.matches(Regex("v?[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")) != true)
            blockers += UpdateRecoveryBlocker.STABLE_VERSION_REQUIRED
        if (source == null) blockers += UpdateRecoveryBlocker.SOURCE_NOT_OBSERVED
        else {
            if (source.scope != scope) blockers += UpdateRecoveryBlocker.EXACT_TARGET_MISSING
            if (source.observedAt.isAfter(now) || Duration.between(source.observedAt, now) >= MAX_AGE)
                blockers += UpdateRecoveryBlocker.STALE_OR_FUTURE_REPORT
            if (source.tools.keys != UpdateRecoveryTool.values().toSet() || source.tools.values.any { it != UpdateRecoveryToolState.AVAILABLE })
                blockers += UpdateRecoveryBlocker.REQUIRED_TOOLS
            val databaseBytes = source.databaseBytes
            if (source.database == UpdateRecoveryDatabaseState.CHANGED_DURING_READ) blockers += UpdateRecoveryBlocker.DATABASE_CHANGED
            else if (source.database != UpdateRecoveryDatabaseState.PRIVATE_REGULAR ||
                databaseBytes == null || databaseBytes !in 1..UpdateRecoverySourceSnapshot.MAX_DATABASE_BYTES)
                blockers += UpdateRecoveryBlocker.DATABASE_ACCESS
            if (source.integrity != DeepDiagnosticDatabaseIntegrityStatus.OK) blockers += UpdateRecoveryBlocker.DATABASE_INTEGRITY
            if (source.schema != DeepDiagnosticDatabaseSchemaStatus.SUPPORTED) blockers += UpdateRecoveryBlocker.DATABASE_SCHEMA
            if (source.runtime != UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT) blockers += UpdateRecoveryBlocker.RUNTIME_FILES
            if (source.panelTls !in setOf(UpdateRecoveryPanelTlsState.NOT_CONFIGURED, UpdateRecoveryPanelTlsState.PAIR_PRESENT))
                blockers += UpdateRecoveryBlocker.PANEL_TLS
        }
        if (blockers.isNotEmpty()) return UpdateRecoveryPlanReview.Blocked(blockers)
        return UpdateRecoveryPlanReview.Draft(UpdateRecoveryDraftPlan(scope, requireNotNull(report.currentVersion),
            requireNotNull(report.architecture), requireNotNull(source).observedAt,
            minOf(report.observedAt, source.observedAt).plus(MAX_AGE)))
    }
}

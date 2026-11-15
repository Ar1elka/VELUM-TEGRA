package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.model.DeepDiagnosticFinding
import com.velumtegra.xuimobile.core.model.DeepDiagnosticOverallStatus
import com.velumtegra.xuimobile.core.model.ManagementBaselineStatus
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import java.time.Instant

/** Existing normalized facts only; no raw outputs, paths, secrets or reconstructed post-death facts. */
data class InspectionReportDetail(
    val identity: ManagementIdentityStatus,
    val baseline: ManagementBaselineStatus,
    val observedAt: Instant,
    val overall: DeepDiagnosticOverallStatus? = null,
    val findings: List<DeepDiagnosticFinding> = emptyList(),
)

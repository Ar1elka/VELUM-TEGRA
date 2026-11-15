package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.model.*
import org.junit.Assert.*
import org.junit.Test

class RecoveryFeedbackTest {
    private val report = RecoveryRegressionFixture.report
    @Test fun exactFreshComparisonExplainsTheNextConfirmationAndExpiry() {
        val text = restoreComparisonFeedback(report, true)
        assertTrue(text.contains("выполнены"))
        assertTrue(text.contains("5 минут"))
        assertTrue(text.contains("отдельному подтверждению"))
    }
    @Test fun changedFilesOrVersionNeverSuggestsProceedingToRestore() {
        for (changed in listOf(report.copy(changedFiles = 1), report.copy(currentVersion = "3.10.0"),
            report.copy(currentSchemaSha256 = "f".repeat(64)))) {
            assertTrue(restoreComparisonFeedback(changed, true).contains("не выполнены"))
        }
    }
    @Test fun expiredMatchingReportRequiresANewComparison() {
        assertTrue(restoreComparisonFeedback(report, false).contains("Выполните новую сверку"))
    }
    @Test fun expectedStoppedPanelListenerDoesNotProduceAFalseMismatch() {
        val stopped = report.copy(serviceState = ManagementServiceState.INACTIVE,
            baselineStatus = ManagementBaselineStatus.Drift(setOf(ManagementBaselineDrift.EXPECTED_LISTENER_ABSENT)))
        assertFalse(restoreComparisonFeedback(stopped, true).contains("не выполнены"))
    }
}

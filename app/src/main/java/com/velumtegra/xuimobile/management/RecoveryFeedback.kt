package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.WorkingDatabaseRestoreConfirmationPolicy
import com.velumtegra.xuimobile.core.model.RestoreCompatibilityReport

/** Explains the same conditions used by the next step; this text grants no write authority. */
internal fun restoreComparisonFeedback(report: RestoreCompatibilityReport, fresh: Boolean): String = when {
    !fresh -> "Сверка завершена, но её срок действия — 5 минут — истёк. Выполните новую сверку перед восстановлением."
    WorkingDatabaseRestoreConfirmationPolicy.structuralReady(report) ->
        "Сверка завершена. Предварительные условия восстановления базы выполнены. В течение 5 минут можно перейти к отдельному подтверждению восстановления."
    else -> "Сверка завершена. Обнаружены различия или неполные сведения: предварительные условия восстановления базы не выполнены."
}

package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.ManagementProbeSpec
import com.velumtegra.xuimobile.core.ssh.ManagementPanelSettingsExit
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutionFailure
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeRunResult

/** Static UI messages only. Neither remote output nor database settings enter a failure message. */
internal object XuiEnrollmentReadFailurePolicy {
    const val SQLITE_UNAVAILABLE = "На сервере не найден sqlite3. Параметры панели не прочитаны."
    const val DATABASE_UNREADABLE = "База панели недоступна для чтения через выбранный SSH-доступ."
    const val QUERY_FAILED = "Не удалось выполнить запрос к базе панели. Проверьте её формат и состояние."
    const val MALFORMED_SETTINGS = "Ответ с параметрами панели имеет неподдерживаемый формат."
    const val TRUNCATED_SETTINGS = "Ответ с параметрами панели превышает допустимый размер."
    const val UNCERTAIN = "Чтение параметров не завершилось с подтверждённым результатом. Повторите проверку."
    const val OTHER = "Не удалось подтвердить параметры установки. Ничего не сохранено."

    fun message(result: ManagementSshProbeRunResult.Failed): String {
        if (result.failedProbe !is ManagementProbeSpec.PanelSettingsReadback) return OTHER
        return when (val failure = result.failure) {
            is ManagementSshProbeExecutionFailure.CommandFailed -> when (failure.exitCode) {
                ManagementPanelSettingsExit.SQLITE_UNAVAILABLE -> SQLITE_UNAVAILABLE
                ManagementPanelSettingsExit.DATABASE_UNREADABLE -> DATABASE_UNREADABLE
                ManagementPanelSettingsExit.QUERY_FAILED -> QUERY_FAILED
                else -> OTHER
            }
            ManagementSshProbeExecutionFailure.MalformedProbeEvidence -> MALFORMED_SETTINGS
            ManagementSshProbeExecutionFailure.OutputTruncated -> TRUNCATED_SETTINGS
            is ManagementSshProbeExecutionFailure.CommandUncertain -> UNCERTAIN
            else -> OTHER
        }
    }
}

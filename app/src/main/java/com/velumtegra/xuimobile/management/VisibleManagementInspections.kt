package com.velumtegra.xuimobile.management

import android.app.Activity
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import kotlinx.coroutines.CancellationException

/** One visible request for one exact saved installation and SSH access. No background entry. */
enum class InspectionKind { QUICK_INSPECT, DEEP_DIAGNOSTIC }

sealed interface InspectionStart {
    data class Accepted(val operationId: String) : InspectionStart
    data class Blocked(val message: String) : InspectionStart
}

/** Status is a projection of the actual operation journal, never a prediction. */
data class InspectionStatus(
    val text: String,
    val terminal: Boolean,
    val succeeded: Boolean = false,
    val serviceState: com.velumtegra.xuimobile.core.model.ManagementServiceState? = null,
    val identity: String? = null,
    val configuration: String? = null,
    val observedAt: java.time.Instant? = null,
    val findingsCount: Int? = null,
    val detail: InspectionReportDetail? = null,
    val completedAt: java.time.Instant? = null,
)

interface VisibleManagementInspectionsPort {
    suspend fun start(
        kind: InspectionKind,
        serverId: String,
        installationId: String,
        serverAccessId: String,
    ): InspectionStart

    suspend fun status(
        kind: InspectionKind,
        operationId: String,
        serverId: String,
        installationId: String,
        serverAccessId: String,
    ): InspectionStatus
}

/** Match every part of the reviewed local tuple before *any* attempt is launched. */
internal fun inspectionReviewMatches(
    review: LocalManagementReview,
    serverId: String,
    installationId: String,
    serverAccessId: String,
): Boolean {
    val ready = review as? LocalManagementReview.Ready ?: return false
    return serverId.isNotBlank() && installationId.isNotBlank() && serverAccessId.isNotBlank() &&
        ready.serverId == serverId && ready.installationId == installationId &&
        serverAccessId in ready.accessIds && ready.accessIds.all { it.isNotBlank() } &&
        ready.accessIds.distinct().size == ready.accessIds.size &&
        ready.managementBindings == ready.accessIds.size &&
        ready.panelPort in 1..65535 && isSafeLocalPanelPath(ready.webBasePath)
}

/** Production integration: existing exact-target launchers and journal projectors. */
internal class ProductionManagementInspectionsPort(
    private val localReview: ManagementLocalReviewPort,
    private val quickLauncher: VisibleManagementQuickInspectOperationLauncher,
    private val deepLauncher: VisibleDeepDiagnosticOperationLauncher,
    private val quickResults: ManagementResultProjector,
    private val deepResults: DeepDiagnosticResultProjector,
) : VisibleManagementInspectionsPort {
    constructor(activity: Activity, app: com.velumtegra.xuimobile.VelumTegraApplication,
        localReview: ManagementLocalReviewPort) : this(
        localReview = localReview,
        quickLauncher = app.visibleManagementQuickInspectOperationLauncher(activity),
        deepLauncher = app.visibleDeepDiagnosticOperationLauncher(activity),
        quickResults = app.managementResultProjector(),
        deepResults = app.deepDiagnosticResultProjector(),
    )

    override suspend fun start(kind: InspectionKind, serverId: String,
        installationId: String, serverAccessId: String): InspectionStart {
        val reviewed = try {
            localReview.readExact(serverId, installationId)
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            return InspectionStart.Blocked("Не удалось повторно проверить локальные записи.")
        }
        if (!inspectionReviewMatches(reviewed, serverId, installationId, serverAccessId)) {
            return InspectionStart.Blocked("Привязка сервера, установки или SSH-доступа изменилась. Обновите сведения.")
        }
        // Each launcher independently revalidates the exact installation/access association
        // immediately before creating the journal record and requesting Android's short service.
        return try {
            when (kind) {
                InspectionKind.QUICK_INSPECT -> when (val response = quickLauncher.start(
                    XuiInstallationId(installationId), ServerAccessId(serverAccessId))) {
                    is ManagementOperationStartResult.Started -> if (response.scope.serverId.value == serverId)
                        InspectionStart.Accepted(response.scope.operationId.value)
                    else InspectionStart.Blocked("Цель операции изменилась. Не доверяйте результатам проверки.")
                    is ManagementOperationStartResult.HostStartNotAccepted ->
                        InspectionStart.Blocked("Android не принял запуск. Операция зарегистрирована, но выполнение не подтверждено.")
                    else -> InspectionStart.Blocked("Запуск проверки отклонён. Проверьте сохранённую установку и SSH-доступ.")
                }
                InspectionKind.DEEP_DIAGNOSTIC -> when (val response = deepLauncher.start(
                    XuiInstallationId(installationId), ServerAccessId(serverAccessId))) {
                    is DeepDiagnosticOperationStartResult.Started -> if (response.scope.serverId.value == serverId)
                        InspectionStart.Accepted(response.scope.operationId.value)
                    else InspectionStart.Blocked("Цель операции изменилась. Не доверяйте результатам проверки.")
                    is DeepDiagnosticOperationStartResult.HostStartNotAccepted ->
                        InspectionStart.Blocked("Android не принял запуск. Операция зарегистрирована, но выполнение не подтверждено.")
                    else -> InspectionStart.Blocked("Запуск диагностики отклонён. Проверьте сохранённую установку и SSH-доступ.")
                }
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            InspectionStart.Blocked("Непредвиденная ошибка запуска. Не повторяйте без проверки состояния VPS.")
        }
    }

    override suspend fun status(kind: InspectionKind, operationId: String,
        serverId: String, installationId: String, serverAccessId: String): InspectionStatus =
        ManagementInspectionStatusReader(quickResults, deepResults).status(
            kind, operationId, serverId, installationId, serverAccessId,
        )
}

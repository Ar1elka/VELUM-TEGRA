package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.discovery.XuiCandidateIdentityEvidence
import com.velumtegra.xuimobile.discovery.XuiReadOnlyDiscoveryPort
import com.velumtegra.xuimobile.discovery.XuiVersionVerificationResult
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPolicy
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import kotlinx.coroutines.CancellationException

fun interface ManagementVersionReadPort {
    suspend fun readExact(
        serverId: String, installationId: String, access: LocalSshAccessSummary,
    ): XuiVersionVerificationResult
}

/** Called only after the screen's version-specific confirmation; reuses the accepted version probe. */
internal class RepositoryManagementVersionReadPort(
    private val review: ManagementLocalReviewPort,
    private val installations: XuiInstallationRepository,
    private val discovery: XuiReadOnlyDiscoveryPort,
) : ManagementVersionReadPort {
    override suspend fun readExact(
        serverId: String, installationId: String, access: LocalSshAccessSummary,
    ): XuiVersionVerificationResult {
        fun blocked(message: String) = XuiVersionVerificationResult.Blocked(message)
        try {
            if (!inspectionReviewMatches(review.readExact(serverId, installationId),
                    serverId, installationId, access.accessId))
                return blocked("Привязка установки или SSH-доступа изменилась.")
            val installation = when (val result = installations.get(XuiInstallationId(installationId))) {
                is RepositoryResult.Success -> result.value.value
                else -> return blocked("Установка больше не найдена.")
            }
            if (installation.id.value != installationId || installation.serverId.value != serverId)
                return blocked("Установка не соответствует выбранному серверу.")
            val identity = installation.identity
            return discovery.verifyVersionExact(
                serverId, access.accessId, access, LiveSshConnectionPolicy.exactTarget(access),
                consent = true,
                candidate = XuiCandidateIdentityEvidence(
                    identity.serviceUnit, identity.binaryPath, identity.rootPath, identity.databasePath,
                ),
            )
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            return blocked("Не удалось подтвердить версию выбранной установки.")
        }
    }
}

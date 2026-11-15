package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpChannelLifecycleProbe
import java.security.MessageDigest

/**
 * Phase 11.34 explicit authorization for exactly one future fixture SFTP channel open/close.
 * No credential bytes, SSH network I/O or SFTP channel are touched here.
 */
internal object SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 10_000L
    const val FIXTURE_LOOPBACK_HOST: String = "127.0.0.1"

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        sshReceipt: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentSftpChannelOpenAuthorizationDraft {
        SiteProductionDeploymentAndroidSshSessionAcquisitionHandoffConsumptionBoundary
            .validateReceipt(sshReceipt)
        require(sshReceipt.singleUseConsumed)
        require(sshReceipt.requiresSeparateSftpChannelOpenBoundary) {
            "Phase 11.32 receipt does not require a separate SFTP channel-open boundary"
        }
        require(serverAccess.id.value == sshReceipt.serverAccessId) { "SFTP authorization ServerAccess mismatch" }
        require(serverAccess.endpoint.host == sshReceipt.remoteHostIdentity) { "SFTP authorization host mismatch" }
        require(serverAccess.endpoint.host == FIXTURE_LOOPBACK_HOST) {
            "Phase 11.34 authorizes only the adb-reverse loopback fixture endpoint"
        }
        require(serverAccess.endpoint.port in 1..65535) { "SFTP authorization fixture port is invalid" }
        require(credentialLease.serverAccessId == sshReceipt.serverAccessId) { "SFTP authorization lease ServerAccess mismatch" }
        require(credentialLease.secretReferenceType == sshReceipt.secretReferenceType) { "SFTP authorization lease auth type mismatch" }
        require(credentialLease.secretReferenceSha256 == sshReceipt.secretReferenceSha256) { "SFTP authorization lease SecretId hash mismatch" }
        require(evaluatedAtEpochMillis >= sshReceipt.consumedAtEpochMillis) { "SFTP authorization cannot predate SSH handoff consumption" }
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "SFTP authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }
        require(canonicalId.matches(authorizationAttemptId)) { "SFTP authorization attempt id must be canonical" }
        require(sshReceipt.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(sshReceipt.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(secretReferenceType(serverAccess) == sshReceipt.secretReferenceType)
        require(secretReferenceSha256(serverAccess) == sshReceipt.secretReferenceSha256) {
            "SFTP authorization raw SecretId binding mismatch"
        }
        require(serverAccessBindingSha256(serverAccess, sshReceipt) == sshReceipt.serverAccessBindingSha256) {
            "SFTP authorization ServerAccess binding mismatch"
        }

        val authorizationExpiresAt = minOf(
            safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis),
            sshReceipt.authorizationExpiresAtEpochMillis,
            credentialLease.authorizationExpiresAtEpochMillis,
        )
        val blockers = buildList {
            if (evaluatedAtEpochMillis > sshReceipt.authorizationExpiresAtEpochMillis ||
                evaluatedAtEpochMillis > credentialLease.authorizationExpiresAtEpochMillis
            ) {
                add(SiteProductionDeploymentSftpChannelOpenAuthorizationBlocker(
                    "SFTP_CHANNEL_CREDENTIAL_WINDOW_EXPIRED",
                    "Credential/SSH-session authorization window expired before SFTP authorization",
                ))
            }
            if (authorizationExpiresAt <= evaluatedAtEpochMillis) {
                add(SiteProductionDeploymentSftpChannelOpenAuthorizationBlocker(
                    "NO_SAFE_SFTP_CHANNEL_AUTHORIZATION_WINDOW",
                    "No positive SFTP channel-open authorization window remains",
                ))
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentSftpChannelOpenAuthorizationStatus.AWAITING_SFTP_CHANNEL_OPEN_APPROVAL
        } else {
            SiteProductionDeploymentSftpChannelOpenAuthorizationStatus.BLOCKED
        }
        val base = SiteProductionDeploymentSftpChannelOpenAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            authorizationOnly = true,
            fixtureEndpointRequired = true,
            credentialLeaseMaterialRead = false,
            authorizesSingleSftpChannelOpenHandoff = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeExecution = true,
            requiresSeparateSftpChannelOpenExecutionBoundary = true,
            requiresSeparateBoundedSftpOperationsBoundary = true,
            requiresSeparateCoordinatorInvocationBoundary = true,
            sshSessionAcquisitionConsumptionReceiptSha256 = sshReceipt.sshSessionAcquisitionConsumptionReceiptSha256,
            resolutionProofSha256 = sshReceipt.resolutionProofSha256,
            serverAccessBindingSha256 = sshReceipt.serverAccessBindingSha256,
            serverAccessId = sshReceipt.serverAccessId,
            remoteHostIdentity = sshReceipt.remoteHostIdentity,
            remotePort = serverAccess.endpoint.port,
            secretReferenceType = sshReceipt.secretReferenceType,
            secretReferenceSha256 = sshReceipt.secretReferenceSha256,
            sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
            exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
            sftpLifecycleProbeImplementation = SiteRemoteSftpChannelLifecycleProbe::class.java.name,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorizationExpiresAt,
            blockers = blockers,
            approvalChallengeSha256 = "",
            draftSha256 = "",
        )
        val challenged = base.copy(approvalChallengeSha256 = approvalChallengeSha256(base))
        return challenged.copy(draftSha256 = draftSha256(challenged)).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentSftpChannelOpenAuthorizationDraft,
        approval: SiteProductionDeploymentSftpChannelOpenApproval,
    ): SiteProductionDeploymentSftpChannelOpenAuthorization {
        validateDraft(draft)
        require(draft.status == SiteProductionDeploymentSftpChannelOpenAuthorizationStatus.AWAITING_SFTP_CHANNEL_OPEN_APPROVAL) {
            "Blocked SFTP channel-open authorization draft cannot be approved"
        }
        require(approval.confirmed) { "SFTP channel-open handoff requires explicit confirmation" }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "SFTP channel-open approval is stale or bound to a different draft"
        }
        val base = SiteProductionDeploymentSftpChannelOpenAuthorization(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentSftpChannelOpenAuthorizationStatus.AUTHORIZED_FOR_SINGLE_SFTP_CHANNEL_OPEN_HANDOFF,
            authorizationOnly = true,
            fixtureEndpointRequired = true,
            credentialLeaseMaterialRead = false,
            authorizesSingleSftpChannelOpenHandoff = true,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeExecution = true,
            requiresSeparateSftpChannelOpenExecutionBoundary = true,
            requiresSeparateBoundedSftpOperationsBoundary = true,
            requiresSeparateCoordinatorInvocationBoundary = true,
            sshSessionAcquisitionConsumptionReceiptSha256 = draft.sshSessionAcquisitionConsumptionReceiptSha256,
            resolutionProofSha256 = draft.resolutionProofSha256,
            serverAccessBindingSha256 = draft.serverAccessBindingSha256,
            serverAccessId = draft.serverAccessId,
            remoteHostIdentity = draft.remoteHostIdentity,
            remotePort = draft.remotePort,
            secretReferenceType = draft.secretReferenceType,
            secretReferenceSha256 = draft.secretReferenceSha256,
            sshConnectionFactoryImplementation = draft.sshConnectionFactoryImplementation,
            exactSessionRegistryImplementation = draft.exactSessionRegistryImplementation,
            sftpLifecycleProbeImplementation = draft.sftpLifecycleProbeImplementation,
            authorizationAttemptId = draft.authorizationAttemptId,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            approvalChallengeSha256 = draft.approvalChallengeSha256,
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base)).also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentSftpChannelOpenAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION)
        require(draft.authorizationOnly && draft.fixtureEndpointRequired)
        require(!draft.credentialLeaseMaterialRead)
        require(!draft.authorizesSingleSftpChannelOpenHandoff)
        require(!draft.authorizesCoordinatorInvocation && !draft.exposesDeployUiAction && !draft.realVpsAccessAllowed)
        require(draft.requiresExplicitApproval && draft.requiresDurableOneShotConsumptionBeforeExecution)
        require(draft.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(draft.requiresSeparateBoundedSftpOperationsBoundary)
        require(draft.requiresSeparateCoordinatorInvocationBoundary)
        require(draft.remoteHostIdentity == FIXTURE_LOOPBACK_HOST && draft.remotePort in 1..65535)
        require(draft.secretReferenceType == "password" || draft.secretReferenceType == "private-key")
        validateHashes(
            draft.sshSessionAcquisitionConsumptionReceiptSha256,
            draft.resolutionProofSha256,
            draft.serverAccessBindingSha256,
            draft.secretReferenceSha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = ""))) { "SFTP authorization draft SHA-256 mismatch" }
    }

    fun validateAuthorization(authorization: SiteProductionDeploymentSftpChannelOpenAuthorization) {
        require(authorization.contractVersion == CONTRACT_VERSION)
        require(authorization.status == SiteProductionDeploymentSftpChannelOpenAuthorizationStatus.AUTHORIZED_FOR_SINGLE_SFTP_CHANNEL_OPEN_HANDOFF)
        require(authorization.authorizationOnly && authorization.fixtureEndpointRequired)
        require(!authorization.credentialLeaseMaterialRead)
        require(authorization.authorizesSingleSftpChannelOpenHandoff)
        require(!authorization.authorizesCoordinatorInvocation && !authorization.exposesDeployUiAction && !authorization.realVpsAccessAllowed)
        require(authorization.requiresDurableOneShotConsumptionBeforeExecution)
        require(authorization.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(authorization.requiresSeparateBoundedSftpOperationsBoundary)
        require(authorization.requiresSeparateCoordinatorInvocationBoundary)
        require(authorization.remoteHostIdentity == FIXTURE_LOOPBACK_HOST && authorization.remotePort in 1..65535)
        validateHashes(
            authorization.sshSessionAcquisitionConsumptionReceiptSha256,
            authorization.resolutionProofSha256,
            authorization.serverAccessBindingSha256,
            authorization.secretReferenceSha256,
            authorization.approvalChallengeSha256,
            authorization.authorizationSha256,
        )
        require(authorization.authorizationSha256 == authorizationSha256(authorization.copy(authorizationSha256 = ""))) {
            "SFTP channel-open authorization SHA-256 mismatch"
        }
    }

    private fun secretReferenceType(serverAccess: ServerAccess): String = when (serverAccess.auth) {
        is SshAuthRef.Password -> "password"
        is SshAuthRef.PrivateKey -> "private-key"
    }

    private fun secretReferenceSha256(serverAccess: ServerAccess): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("secretReferenceType=").append(secretReferenceType(serverAccess)).append('\n')
        append("secretId=").append(serverAccess.auth.secretId.value).append('\n')
    })

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        receipt: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt,
    ): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("serverId=").append(serverAccess.serverId.value).append('\n')
        append("host=").append(serverAccess.endpoint.host).append('\n')
        append("port=").append(serverAccess.endpoint.port).append('\n')
        append("username=").append(serverAccess.username).append('\n')
        append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
        append("pinnedHostKey=").append(serverAccess.pinnedHostKey.value).append('\n')
    })

    private fun approvalChallengeSha256(draft: SiteProductionDeploymentSftpChannelOpenAuthorizationDraft): String =
        sha256("sftp-channel-open-approval\n" + canonicalDraft(draft.copy(approvalChallengeSha256 = "", draftSha256 = "")))

    private fun draftSha256(draft: SiteProductionDeploymentSftpChannelOpenAuthorizationDraft): String =
        sha256(canonicalDraft(draft.copy(draftSha256 = "")))

    private fun canonicalDraft(draft: SiteProductionDeploymentSftpChannelOpenAuthorizationDraft): String = buildString {
        append("contractVersion=").append(draft.contractVersion).append('\n')
        append("status=").append(draft.status.name).append('\n')
        append("sshReceipt=").append(draft.sshSessionAcquisitionConsumptionReceiptSha256).append('\n')
        append("resolutionProof=").append(draft.resolutionProofSha256).append('\n')
        append("serverAccessBinding=").append(draft.serverAccessBindingSha256).append('\n')
        append("serverAccessId=").append(draft.serverAccessId).append('\n')
        append("host=").append(draft.remoteHostIdentity).append('\n')
        append("port=").append(draft.remotePort).append('\n')
        append("secretReferenceType=").append(draft.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(draft.secretReferenceSha256).append('\n')
        append("sshFactory=").append(draft.sshConnectionFactoryImplementation).append('\n')
        append("registry=").append(draft.exactSessionRegistryImplementation).append('\n')
        append("sftpProbe=").append(draft.sftpLifecycleProbeImplementation).append('\n')
        append("attempt=").append(draft.authorizationAttemptId).append('\n')
        append("evaluatedAt=").append(draft.evaluatedAtEpochMillis).append('\n')
        append("expiresAt=").append(draft.authorizationExpiresAtEpochMillis).append('\n')
        append("blockers=").append(draft.blockers.joinToString("|") { "${it.code}:${it.detail}" }).append('\n')
        append("challenge=").append(draft.approvalChallengeSha256).append('\n')
    }

    private fun authorizationSha256(authorization: SiteProductionDeploymentSftpChannelOpenAuthorization): String = sha256(buildString {
        append("contractVersion=").append(authorization.contractVersion).append('\n')
        append("status=").append(authorization.status.name).append('\n')
        append("sshReceipt=").append(authorization.sshSessionAcquisitionConsumptionReceiptSha256).append('\n')
        append("resolutionProof=").append(authorization.resolutionProofSha256).append('\n')
        append("serverAccessBinding=").append(authorization.serverAccessBindingSha256).append('\n')
        append("serverAccessId=").append(authorization.serverAccessId).append('\n')
        append("host=").append(authorization.remoteHostIdentity).append('\n')
        append("port=").append(authorization.remotePort).append('\n')
        append("secretReferenceType=").append(authorization.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(authorization.secretReferenceSha256).append('\n')
        append("sshFactory=").append(authorization.sshConnectionFactoryImplementation).append('\n')
        append("registry=").append(authorization.exactSessionRegistryImplementation).append('\n')
        append("sftpProbe=").append(authorization.sftpLifecycleProbeImplementation).append('\n')
        append("attempt=").append(authorization.authorizationAttemptId).append('\n')
        append("evaluatedAt=").append(authorization.evaluatedAtEpochMillis).append('\n')
        append("expiresAt=").append(authorization.authorizationExpiresAtEpochMillis).append('\n')
        append("challenge=").append(authorization.approvalChallengeSha256).append('\n')
        append("authorizesSingleSftpChannelOpenHandoff=").append(authorization.authorizesSingleSftpChannelOpenHandoff).append('\n')
    })

    private fun safeAdd(left: Long, right: Long): Long = if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right
    private fun validateHashes(vararg values: String) = require(values.all(sha256Pattern::matches)) {
        "SFTP channel-open authorization hashes must be lowercase SHA-256"
    }
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

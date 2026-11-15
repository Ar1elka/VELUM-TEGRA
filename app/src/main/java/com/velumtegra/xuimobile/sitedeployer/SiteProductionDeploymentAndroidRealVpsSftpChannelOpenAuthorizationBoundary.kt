package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpChannelLifecycleProbe
import java.security.MessageDigest

/**
 * Phase 11.45 non-network authorization for one future real-VPS SFTP channel-open handoff.
 *
 * The boundary accepts only a verified-and-closed Phase 11.44 SSH execution proof. That proof is
 * evidence that the exact reviewed endpoint and host-key pin were reached successfully; no live
 * session or credential material is retained across the boundary. Explicit approval authorizes only
 * a future durable handoff. A later execution boundary must obtain a fresh credential lease and a
 * fresh SSH session before it may open one SFTP channel.
 */
internal object SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 15_000L

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        sshExecutionProof: SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionProof,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft {
        SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionExecutionBoundary
            .validateProof(sshExecutionProof)
        require(
            sshExecutionProof.status ==
                SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionStatus
                    .REAL_VPS_SESSION_ACQUIRED_VERIFIED_REGISTERED_AND_CLOSED,
        ) { "Real-VPS SFTP authorization requires the exact successful Phase 11.44 proof" }
        require(sshExecutionProof.productionNetworkTouched)
        require(sshExecutionProof.hostKeyPinVerifiedAgainstRemote)
        require(sshExecutionProof.sshSessionAcquisitionExecuted)
        require(sshExecutionProof.sessionClosed)
        require(!sshExecutionProof.sftpChannelOpened)
        require(!sshExecutionProof.remoteReadPerformed)
        require(!sshExecutionProof.mutationPerformed)
        require(sshExecutionProof.requiresSeparateSftpChannelOpenBoundary)
        require(canonicalId.matches(authorizationAttemptId)) {
            "Real-VPS SFTP authorization attempt id must be a canonical 8..128 character identifier"
        }
        require(evaluatedAtEpochMillis >= sshExecutionProof.executedAtEpochMillis) {
            "Real-VPS SFTP authorization cannot predate the Phase 11.44 execution proof"
        }
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "Real-VPS SFTP authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }
        require(serverAccess.id.value == sshExecutionProof.serverAccessId) {
            "Real-VPS SFTP authorization ServerAccess mismatch"
        }
        require(serverAccess.endpoint.host == sshExecutionProof.remoteHostIdentity) {
            "Real-VPS SFTP authorization host mismatch"
        }
        require(serverAccess.endpoint.port == sshExecutionProof.remotePort) {
            "Real-VPS SFTP authorization port mismatch"
        }
        require(serverAccess.username == sshExecutionProof.username) {
            "Real-VPS SFTP authorization username mismatch"
        }
        require(!isLoopbackHost(serverAccess.endpoint.host)) {
            "Phase 11.45 requires the exact reviewed non-loopback real-VPS endpoint"
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == sshExecutionProof.secretReferenceType) {
            "Real-VPS SFTP authorization auth type drifted"
        }
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        require(secretReferenceSha256 == sshExecutionProof.secretReferenceSha256) {
            "Real-VPS SFTP authorization SecretId binding drifted"
        }
        val pinnedHostKeySha256 = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }
        require(pinnedHostKeySha256 == sshExecutionProof.pinnedHostKeySha256)
        require(pinnedHostKeySha256 == sshExecutionProof.verifiedHostKeySha256) {
            "Real-VPS SFTP authorization requires the exact previously verified live host-key pin"
        }
        require(
            serverAccessBindingSha256(
                serverAccess = serverAccess,
                secretReferenceType = secretReferenceType,
                secretReferenceSha256 = secretReferenceSha256,
                pinnedHostKeySha256 = pinnedHostKeySha256,
            ) == sshExecutionProof.serverAccessBindingSha256,
        ) { "Real-VPS SFTP authorization ServerAccess binding drifted after Phase 11.44" }
        require(sshExecutionProof.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(sshExecutionProof.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)

        val authorizationExpiresAt = safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis)
        val base = SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus
                .AWAITING_EXPLICIT_SFTP_CHANNEL_OPEN_APPROVAL,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemoteByPriorProof = true,
            authorizesNetworkAccess = false,
            authorizesSftpChannelOpen = false,
            authorizesSingleSftpChannelOpenHandoff = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeSftpChannelOpen = true,
            requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution = true,
            requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution = true,
            requiresSeparateSftpChannelOpenExecutionBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            priorSshExecutionProofSha256 = sshExecutionProof.executionProofSha256,
            priorSshExecutionReceiptSha256 = sshExecutionProof.sshSessionAcquisitionConsumptionReceiptSha256,
            serverAccessBindingSha256 = sshExecutionProof.serverAccessBindingSha256,
            requestSha256 = sshExecutionProof.requestSha256,
            capabilityProfileSha256 = sshExecutionProof.capabilityProfileSha256,
            serverAccessId = sshExecutionProof.serverAccessId,
            remoteHostIdentity = sshExecutionProof.remoteHostIdentity,
            remotePort = sshExecutionProof.remotePort,
            username = sshExecutionProof.username,
            pinnedHostKeySha256 = pinnedHostKeySha256,
            secretReferenceType = sshExecutionProof.secretReferenceType,
            secretReferenceSha256 = sshExecutionProof.secretReferenceSha256,
            sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
            exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
            sftpLifecycleProbeImplementation = SiteRemoteSftpChannelLifecycleProbe::class.java.name,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorizationExpiresAt,
            blockers = emptyList(),
            approvalChallengeSha256 = "",
            draftSha256 = "",
        )
        val challenged = base.copy(approvalChallengeSha256 = approvalChallengeSha256(base))
        return challenged.copy(draftSha256 = draftSha256(challenged)).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsSftpChannelOpenApproval,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization {
        validateDraft(draft)
        require(
            draft.status == SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus
                .AWAITING_EXPLICIT_SFTP_CHANNEL_OPEN_APPROVAL,
        ) { "Blocked real-VPS SFTP channel-open authorization draft cannot be approved" }
        require(approval.confirmed) { "Real-VPS SFTP channel-open handoff requires explicit confirmation" }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "Real-VPS SFTP channel-open approval is stale or bound to a different draft"
        }
        val base = SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_SFTP_CHANNEL_OPEN_HANDOFF,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemoteByPriorProof = true,
            authorizesNetworkAccess = false,
            authorizesSftpChannelOpen = false,
            authorizesSingleSftpChannelOpenHandoff = true,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeSftpChannelOpen = true,
            requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution = true,
            requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution = true,
            requiresSeparateSftpChannelOpenExecutionBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            priorSshExecutionProofSha256 = draft.priorSshExecutionProofSha256,
            priorSshExecutionReceiptSha256 = draft.priorSshExecutionReceiptSha256,
            serverAccessBindingSha256 = draft.serverAccessBindingSha256,
            requestSha256 = draft.requestSha256,
            capabilityProfileSha256 = draft.capabilityProfileSha256,
            serverAccessId = draft.serverAccessId,
            remoteHostIdentity = draft.remoteHostIdentity,
            remotePort = draft.remotePort,
            username = draft.username,
            pinnedHostKeySha256 = draft.pinnedHostKeySha256,
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

    fun validateDraft(draft: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION)
        require(draft.status != SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus.BLOCKED)
        require(draft.authorizationOnly)
        require(!draft.credentialLeaseMaterialRead)
        require(!draft.productionNetworkTouched)
        require(draft.hostKeyPinVerifiedAgainstRemoteByPriorProof)
        require(!draft.authorizesNetworkAccess)
        require(!draft.authorizesSftpChannelOpen)
        require(!draft.authorizesSingleSftpChannelOpenHandoff)
        require(!draft.authorizesReadOnlyPreflightExecution)
        require(!draft.authorizesMutation)
        require(!draft.authorizesCoordinatorInvocation)
        require(!draft.exposesDeployUiAction)
        require(!draft.realVpsAccessAllowed)
        require(draft.requiresExplicitApproval)
        require(draft.requiresDurableOneShotConsumptionBeforeSftpChannelOpen)
        require(draft.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution)
        require(draft.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution)
        require(draft.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(draft.requiresSeparateReadOnlyExecutionBoundary)
        require(draft.requiresSeparateMutationBoundary)
        require(!isLoopbackHost(draft.remoteHostIdentity))
        require(draft.remotePort in 1..65535)
        require(draft.username.isNotBlank())
        require(draft.authorizationExpiresAtEpochMillis > draft.evaluatedAtEpochMillis)
        require(draft.blockers.isEmpty())
        require(draft.secretReferenceType == "password" || draft.secretReferenceType == "private-key")
        require(draft.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(draft.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(draft.sftpLifecycleProbeImplementation == SiteRemoteSftpChannelLifecycleProbe::class.java.name)
        validateHashes(
            draft.priorSshExecutionProofSha256,
            draft.priorSshExecutionReceiptSha256,
            draft.serverAccessBindingSha256,
            draft.requestSha256,
            draft.capabilityProfileSha256,
            draft.pinnedHostKeySha256,
            draft.secretReferenceSha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(draft.approvalChallengeSha256 == approvalChallengeSha256(draft.copy(
            approvalChallengeSha256 = "",
            draftSha256 = "",
        )))
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = "")))
    }

    fun validateAuthorization(authorization: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization) {
        require(authorization.contractVersion == CONTRACT_VERSION)
        require(
            authorization.status == SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_SFTP_CHANNEL_OPEN_HANDOFF,
        )
        require(authorization.authorizationOnly)
        require(!authorization.credentialLeaseMaterialRead)
        require(!authorization.productionNetworkTouched)
        require(authorization.hostKeyPinVerifiedAgainstRemoteByPriorProof)
        require(!authorization.authorizesNetworkAccess)
        require(!authorization.authorizesSftpChannelOpen)
        require(authorization.authorizesSingleSftpChannelOpenHandoff)
        require(!authorization.authorizesReadOnlyPreflightExecution)
        require(!authorization.authorizesMutation)
        require(!authorization.authorizesCoordinatorInvocation)
        require(!authorization.exposesDeployUiAction)
        require(!authorization.realVpsAccessAllowed)
        require(authorization.requiresDurableOneShotConsumptionBeforeSftpChannelOpen)
        require(authorization.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution)
        require(authorization.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution)
        require(authorization.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(authorization.requiresSeparateReadOnlyExecutionBoundary)
        require(authorization.requiresSeparateMutationBoundary)
        require(!isLoopbackHost(authorization.remoteHostIdentity))
        require(authorization.remotePort in 1..65535)
        require(authorization.authorizationExpiresAtEpochMillis > authorization.evaluatedAtEpochMillis)
        require(authorization.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(authorization.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(authorization.sftpLifecycleProbeImplementation == SiteRemoteSftpChannelLifecycleProbe::class.java.name)
        validateHashes(
            authorization.priorSshExecutionProofSha256,
            authorization.priorSshExecutionReceiptSha256,
            authorization.serverAccessBindingSha256,
            authorization.requestSha256,
            authorization.capabilityProfileSha256,
            authorization.pinnedHostKeySha256,
            authorization.secretReferenceSha256,
            authorization.approvalChallengeSha256,
            authorization.authorizationSha256,
        )
        require(
            authorization.authorizationSha256 == authorizationSha256(authorization.copy(authorizationSha256 = "")),
        ) { "Real-VPS SFTP channel-open authorization SHA-256 mismatch" }
    }

    private fun approvalChallengeSha256(
        draft: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft,
    ): String = sha256(buildString {
        append("phase=11.45\n")
        append("purpose=real-vps-sftp-channel-open-approval\n")
        append("priorSshExecutionProofSha256=").append(draft.priorSshExecutionProofSha256).append('\n')
        append("serverAccessBindingSha256=").append(draft.serverAccessBindingSha256).append('\n')
        append("sftpProbe=").append(draft.sftpLifecycleProbeImplementation).append('\n')
        append("attemptId=").append(draft.authorizationAttemptId).append('\n')
        append("evaluatedAt=").append(draft.evaluatedAtEpochMillis).append('\n')
        append("expiresAt=").append(draft.authorizationExpiresAtEpochMillis).append('\n')
    })

    private fun draftSha256(draft: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft): String =
        sha256(buildString {
            append("phase=11.45\n")
            append("status=").append(draft.status.name).append('\n')
            append("priorSshExecutionProofSha256=").append(draft.priorSshExecutionProofSha256).append('\n')
            append("priorSshExecutionReceiptSha256=").append(draft.priorSshExecutionReceiptSha256).append('\n')
            append("serverAccessBindingSha256=").append(draft.serverAccessBindingSha256).append('\n')
            append("requestSha256=").append(draft.requestSha256).append('\n')
            append("capabilityProfileSha256=").append(draft.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(draft.serverAccessId).append('\n')
            append("host=").append(draft.remoteHostIdentity).append('\n')
            append("port=").append(draft.remotePort).append('\n')
            append("username=").append(draft.username).append('\n')
            append("pinnedHostKeySha256=").append(draft.pinnedHostKeySha256).append('\n')
            append("secretReferenceType=").append(draft.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(draft.secretReferenceSha256).append('\n')
            append("sftpProbe=").append(draft.sftpLifecycleProbeImplementation).append('\n')
            append("attemptId=").append(draft.authorizationAttemptId).append('\n')
            append("evaluatedAt=").append(draft.evaluatedAtEpochMillis).append('\n')
            append("expiresAt=").append(draft.authorizationExpiresAtEpochMillis).append('\n')
            append("approvalChallengeSha256=").append(draft.approvalChallengeSha256).append('\n')
        })

    private fun authorizationSha256(
        authorization: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization,
    ): String = sha256(buildString {
        append("phase=11.45\n")
        append("status=").append(authorization.status.name).append('\n')
        append("priorSshExecutionProofSha256=").append(authorization.priorSshExecutionProofSha256).append('\n')
        append("priorSshExecutionReceiptSha256=").append(authorization.priorSshExecutionReceiptSha256).append('\n')
        append("serverAccessBindingSha256=").append(authorization.serverAccessBindingSha256).append('\n')
        append("requestSha256=").append(authorization.requestSha256).append('\n')
        append("capabilityProfileSha256=").append(authorization.capabilityProfileSha256).append('\n')
        append("serverAccessId=").append(authorization.serverAccessId).append('\n')
        append("host=").append(authorization.remoteHostIdentity).append('\n')
        append("port=").append(authorization.remotePort).append('\n')
        append("username=").append(authorization.username).append('\n')
        append("pinnedHostKeySha256=").append(authorization.pinnedHostKeySha256).append('\n')
        append("secretReferenceType=").append(authorization.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(authorization.secretReferenceSha256).append('\n')
        append("sshFactory=").append(authorization.sshConnectionFactoryImplementation).append('\n')
        append("registry=").append(authorization.exactSessionRegistryImplementation).append('\n')
        append("sftpProbe=").append(authorization.sftpLifecycleProbeImplementation).append('\n')
        append("attemptId=").append(authorization.authorizationAttemptId).append('\n')
        append("evaluatedAt=").append(authorization.evaluatedAtEpochMillis).append('\n')
        append("expiresAt=").append(authorization.authorizationExpiresAtEpochMillis).append('\n')
        append("approvalChallengeSha256=").append(authorization.approvalChallengeSha256).append('\n')
    })

    private fun secretReferenceSha256(
        serverAccessId: String,
        secretReferenceType: String,
        secretIdValue: String,
    ): String = sha256(buildString {
        append("serverAccessId=").append(serverAccessId).append('\n')
        append("secretReferenceType=").append(secretReferenceType).append('\n')
        append("secretId=").append(secretIdValue).append('\n')
    })

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        secretReferenceType: String,
        secretReferenceSha256: String,
        pinnedHostKeySha256: String,
    ): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("serverId=").append(serverAccess.serverId.value).append('\n')
        append("host=").append(serverAccess.endpoint.host).append('\n')
        append("port=").append(serverAccess.endpoint.port).append('\n')
        append("username=").append(serverAccess.username).append('\n')
        append("secretReferenceType=").append(secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
        append("pinnedHostKeySha256=").append(pinnedHostKeySha256).append('\n')
    })

    private fun safeAdd(left: Long, right: Long): Long =
        if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.lowercase()
        return normalized == "localhost" || normalized == "::1" || normalized == "[::1]" ||
            normalized.startsWith("127.")
    }

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS SFTP channel-open authorization hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

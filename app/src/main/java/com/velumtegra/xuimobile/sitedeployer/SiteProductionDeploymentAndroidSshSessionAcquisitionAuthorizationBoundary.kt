package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import java.security.MessageDigest

/**
 * Phase 11.31 non-network SSH-session acquisition authorization boundary.
 *
 * It binds the exact successful Phase 11.30 resolution proof and ephemeral lease metadata to the
 * exact public ServerAccess plus reviewed JSch/ExactSessionRegistry implementation identities.
 * Explicit approval authorizes only one future handoff. This boundary never reads lease material,
 * never invokes JSch, never touches the session registry, never opens SSH/SFTP, and never accesses
 * a real VPS. Durable one-shot handoff consumption and acquisition execution remain separate phases.
 */
internal object SiteProductionDeploymentAndroidSshSessionAcquisitionAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 15_000L

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        resolutionProof: SiteProductionDeploymentCredentialResolutionExecutionProof,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft {
        SiteProductionDeploymentAndroidCredentialResolutionExecutionBoundary.validateProof(resolutionProof)
        require(
            resolutionProof.status ==
                SiteProductionDeploymentCredentialResolutionExecutionStatus.RESOLVED_TO_EPHEMERAL_LEASE,
        ) { "Only a successfully resolved credential may enter SSH-session authorization" }
        require(resolutionProof.requiresSeparateSshSessionAcquisitionBoundary) {
            "Credential-resolution proof does not require this SSH-session boundary"
        }
        require(composition.descriptorSha256 == resolutionProof.compositionDescriptorSha256) {
            "SSH-session authorization composition descriptor mismatch"
        }
        require(composition.serverIdentitySha256 == resolutionProof.serverIdentitySha256) {
            "SSH-session authorization server identity mismatch"
        }
        require(serverAccess.id.value == resolutionProof.serverAccessId) {
            "SSH-session authorization ServerAccess mismatch"
        }
        require(credentialLease.serverAccessId == resolutionProof.serverAccessId) {
            "SSH-session authorization credential lease ServerAccess mismatch"
        }
        require(credentialLease.secretReferenceType == resolutionProof.secretReferenceType) {
            "SSH-session authorization credential lease auth type mismatch"
        }
        require(credentialLease.secretReferenceSha256 == resolutionProof.secretReferenceSha256) {
            "SSH-session authorization credential lease SecretId hash mismatch"
        }
        require(
            credentialLease.credentialResolutionConsumptionReceiptSha256 ==
                resolutionProof.credentialResolutionConsumptionReceiptSha256,
        ) { "SSH-session authorization credential lease receipt mismatch" }
        require(credentialLease.resolvedAtEpochMillis == resolutionProof.resolvedAtEpochMillis) {
            "SSH-session authorization credential lease resolution time mismatch"
        }
        require(
            credentialLease.authorizationExpiresAtEpochMillis ==
                resolutionProof.authorizationExpiresAtEpochMillis,
        ) { "SSH-session authorization credential lease expiry mismatch" }
        require(canonicalId.matches(authorizationAttemptId)) {
            "SSH-session authorization attempt id must be a canonical 8..128 character identifier"
        }
        require(evaluatedAtEpochMillis >= resolutionProof.resolvedAtEpochMillis) {
            "SSH-session authorization cannot predate credential resolution"
        }
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "SSH-session authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }

        val requestedExpiry = safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis)
        val authorizationExpiresAt =
            minOf(requestedExpiry, resolutionProof.authorizationExpiresAtEpochMillis)
        val blockers = buildList {
            if (evaluatedAtEpochMillis > resolutionProof.authorizationExpiresAtEpochMillis) {
                add(
                    SiteProductionDeploymentSshSessionAcquisitionAuthorizationBlocker(
                        code = "SSH_SESSION_CREDENTIAL_WINDOW_EXPIRED",
                        detail = "Credential-resolution authorization expired before SSH-session authorization",
                    ),
                )
            }
            if (authorizationExpiresAt <= evaluatedAtEpochMillis) {
                add(
                    SiteProductionDeploymentSshSessionAcquisitionAuthorizationBlocker(
                        code = "NO_SAFE_SSH_SESSION_AUTHORIZATION_WINDOW",
                        detail = "No positive SSH-session authorization window remains",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentSshSessionAcquisitionAuthorizationStatus
                .AWAITING_SSH_SESSION_ACQUISITION_APPROVAL
        } else {
            SiteProductionDeploymentSshSessionAcquisitionAuthorizationStatus.BLOCKED
        }

        val base = SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesSshSessionAcquisition = false,
            authorizesSingleSshSessionAcquisitionHandoff = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeSshSessionAcquisition = true,
            requiresSeparateSshSessionAcquisitionExecutionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            resolutionProofSha256 = resolutionProof.resolutionProofSha256,
            credentialResolutionConsumptionReceiptSha256 =
                resolutionProof.credentialResolutionConsumptionReceiptSha256,
            serverIdentitySha256 = resolutionProof.serverIdentitySha256,
            compositionDescriptorSha256 = resolutionProof.compositionDescriptorSha256,
            serverAccessBindingSha256 = serverAccessBindingSha256(serverAccess, resolutionProof),
            serverAccessId = resolutionProof.serverAccessId,
            runtimeSessionId = composition.runtimeIdentity.runtimeSessionId,
            remoteHostIdentity = serverAccess.endpoint.host,
            secretReferenceType = resolutionProof.secretReferenceType,
            secretReferenceSha256 = resolutionProof.secretReferenceSha256,
            credentialStoreImplementation = resolutionProof.credentialStoreImplementation,
            sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
            exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorizationExpiresAt,
            blockers = blockers,
            approvalChallengeSha256 = "",
            draftSha256 = "",
        )
        val challenge = approvalChallengeSha256(base)
        val withChallenge = base.copy(approvalChallengeSha256 = challenge)
        return withChallenge.copy(draftSha256 = draftSha256(withChallenge)).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft,
        approval: SiteProductionDeploymentSshSessionAcquisitionApproval,
    ): SiteProductionDeploymentSshSessionAcquisitionAuthorization {
        validateDraft(draft)
        require(
            draft.status ==
                SiteProductionDeploymentSshSessionAcquisitionAuthorizationStatus
                    .AWAITING_SSH_SESSION_ACQUISITION_APPROVAL,
        ) { "Blocked SSH-session authorization draft cannot be approved" }
        require(approval.confirmed) { "SSH-session acquisition handoff requires explicit confirmation" }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "SSH-session acquisition approval is stale or bound to a different draft"
        }

        val base = SiteProductionDeploymentSshSessionAcquisitionAuthorization(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentSshSessionAcquisitionAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_SSH_SESSION_ACQUISITION_HANDOFF,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesSshSessionAcquisition = false,
            authorizesSingleSshSessionAcquisitionHandoff = true,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeSshSessionAcquisition = true,
            requiresSeparateSshSessionAcquisitionExecutionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            resolutionProofSha256 = draft.resolutionProofSha256,
            credentialResolutionConsumptionReceiptSha256 =
                draft.credentialResolutionConsumptionReceiptSha256,
            serverIdentitySha256 = draft.serverIdentitySha256,
            compositionDescriptorSha256 = draft.compositionDescriptorSha256,
            serverAccessBindingSha256 = draft.serverAccessBindingSha256,
            serverAccessId = draft.serverAccessId,
            runtimeSessionId = draft.runtimeSessionId,
            remoteHostIdentity = draft.remoteHostIdentity,
            secretReferenceType = draft.secretReferenceType,
            secretReferenceSha256 = draft.secretReferenceSha256,
            credentialStoreImplementation = draft.credentialStoreImplementation,
            sshConnectionFactoryImplementation = draft.sshConnectionFactoryImplementation,
            exactSessionRegistryImplementation = draft.exactSessionRegistryImplementation,
            authorizationAttemptId = draft.authorizationAttemptId,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            approvalChallengeSha256 = draft.approvalChallengeSha256,
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base))
            .also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION)
        require(draft.authorizationOnly)
        require(!draft.credentialLeaseMaterialRead)
        require(!draft.productionTransportEnabled)
        require(!draft.authorizesTransport)
        require(!draft.authorizesSshSessionAcquisition)
        require(!draft.authorizesSingleSshSessionAcquisitionHandoff)
        require(!draft.authorizesSftpChannelOpen)
        require(!draft.authorizesCoordinatorInvocation)
        require(!draft.exposesDeployUiAction)
        require(!draft.realVpsAccessAllowed)
        require(draft.requiresExplicitApproval)
        require(draft.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition)
        require(draft.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        require(draft.requiresSeparateSftpChannelOpenBoundary)
        require(draft.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(draft.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        validateHashes(
            draft.resolutionProofSha256,
            draft.credentialResolutionConsumptionReceiptSha256,
            draft.serverIdentitySha256,
            draft.compositionDescriptorSha256,
            draft.serverAccessBindingSha256,
            draft.secretReferenceSha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = ""))) {
            "SSH-session authorization draft SHA-256 mismatch"
        }
    }

    fun validateAuthorization(
        authorization: SiteProductionDeploymentSshSessionAcquisitionAuthorization,
    ) {
        require(authorization.contractVersion == CONTRACT_VERSION)
        require(
            authorization.status ==
                SiteProductionDeploymentSshSessionAcquisitionAuthorizationStatus
                    .AUTHORIZED_FOR_SINGLE_SSH_SESSION_ACQUISITION_HANDOFF,
        )
        require(authorization.authorizationOnly)
        require(!authorization.credentialLeaseMaterialRead)
        require(!authorization.productionTransportEnabled)
        require(!authorization.authorizesTransport)
        require(!authorization.authorizesSshSessionAcquisition)
        require(authorization.authorizesSingleSshSessionAcquisitionHandoff)
        require(!authorization.authorizesSftpChannelOpen)
        require(!authorization.authorizesCoordinatorInvocation)
        require(!authorization.exposesDeployUiAction)
        require(!authorization.realVpsAccessAllowed)
        require(authorization.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition)
        require(authorization.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        require(authorization.requiresSeparateSftpChannelOpenBoundary)
        require(
            authorization.sshConnectionFactoryImplementation ==
                JschSshConnectionFactory::class.java.name,
        )
        require(
            authorization.exactSessionRegistryImplementation ==
                ExactSessionRegistry::class.java.name,
        )
        validateHashes(
            authorization.resolutionProofSha256,
            authorization.credentialResolutionConsumptionReceiptSha256,
            authorization.serverIdentitySha256,
            authorization.compositionDescriptorSha256,
            authorization.serverAccessBindingSha256,
            authorization.secretReferenceSha256,
            authorization.approvalChallengeSha256,
            authorization.authorizationSha256,
        )
        require(
            authorization.authorizationSha256 ==
                authorizationSha256(authorization.copy(authorizationSha256 = "")),
        ) { "SSH-session acquisition authorization SHA-256 mismatch" }
    }

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        proof: SiteProductionDeploymentCredentialResolutionExecutionProof,
    ): String = sha256(
        buildString {
            append("serverAccessId=").append(serverAccess.id.value).append('\n')
            append("serverId=").append(serverAccess.serverId.value).append('\n')
            append("host=").append(serverAccess.endpoint.host).append('\n')
            append("port=").append(serverAccess.endpoint.port).append('\n')
            append("username=").append(serverAccess.username).append('\n')
            append("secretReferenceType=").append(proof.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(proof.secretReferenceSha256).append('\n')
            append("pinnedHostKey=").append(serverAccess.pinnedHostKey.value).append('\n')
        },
    )

    private fun approvalChallengeSha256(
        draft: SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft,
    ): String = sha256(
        "ssh-session-acquisition-approval\n" + canonicalDraft(draft.copy(
            approvalChallengeSha256 = "",
            draftSha256 = "",
        )),
    )

    private fun draftSha256(
        draft: SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft,
    ): String = sha256(canonicalDraft(draft.copy(draftSha256 = "")))

    private fun authorizationSha256(
        authorization: SiteProductionDeploymentSshSessionAcquisitionAuthorization,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(authorization.contractVersion).append('\n')
            append("status=").append(authorization.status.name).append('\n')
            append("resolutionProofSha256=").append(authorization.resolutionProofSha256).append('\n')
            append("credentialResolutionConsumptionReceiptSha256=")
                .append(authorization.credentialResolutionConsumptionReceiptSha256).append('\n')
            append("serverIdentitySha256=").append(authorization.serverIdentitySha256).append('\n')
            append("compositionDescriptorSha256=").append(authorization.compositionDescriptorSha256).append('\n')
            append("serverAccessBindingSha256=").append(authorization.serverAccessBindingSha256).append('\n')
            append("serverAccessId=").append(authorization.serverAccessId).append('\n')
            append("runtimeSessionId=").append(authorization.runtimeSessionId).append('\n')
            append("remoteHostIdentity=").append(authorization.remoteHostIdentity).append('\n')
            append("secretReferenceType=").append(authorization.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(authorization.secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(authorization.credentialStoreImplementation).append('\n')
            append("sshConnectionFactoryImplementation=")
                .append(authorization.sshConnectionFactoryImplementation).append('\n')
            append("exactSessionRegistryImplementation=")
                .append(authorization.exactSessionRegistryImplementation).append('\n')
            append("authorizationAttemptId=").append(authorization.authorizationAttemptId).append('\n')
            append("evaluatedAtEpochMillis=").append(authorization.evaluatedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=")
                .append(authorization.authorizationExpiresAtEpochMillis).append('\n')
            append("approvalChallengeSha256=").append(authorization.approvalChallengeSha256).append('\n')
            append("authorizesSingleSshSessionAcquisitionHandoff=")
                .append(authorization.authorizesSingleSshSessionAcquisitionHandoff).append('\n')
        },
    )

    private fun canonicalDraft(
        draft: SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft,
    ): String = buildString {
        append("contractVersion=").append(draft.contractVersion).append('\n')
        append("status=").append(draft.status.name).append('\n')
        append("resolutionProofSha256=").append(draft.resolutionProofSha256).append('\n')
        append("credentialResolutionConsumptionReceiptSha256=")
            .append(draft.credentialResolutionConsumptionReceiptSha256).append('\n')
        append("serverIdentitySha256=").append(draft.serverIdentitySha256).append('\n')
        append("compositionDescriptorSha256=").append(draft.compositionDescriptorSha256).append('\n')
        append("serverAccessBindingSha256=").append(draft.serverAccessBindingSha256).append('\n')
        append("serverAccessId=").append(draft.serverAccessId).append('\n')
        append("runtimeSessionId=").append(draft.runtimeSessionId).append('\n')
        append("remoteHostIdentity=").append(draft.remoteHostIdentity).append('\n')
        append("secretReferenceType=").append(draft.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(draft.secretReferenceSha256).append('\n')
        append("credentialStoreImplementation=").append(draft.credentialStoreImplementation).append('\n')
        append("sshConnectionFactoryImplementation=").append(draft.sshConnectionFactoryImplementation).append('\n')
        append("exactSessionRegistryImplementation=").append(draft.exactSessionRegistryImplementation).append('\n')
        append("authorizationAttemptId=").append(draft.authorizationAttemptId).append('\n')
        append("evaluatedAtEpochMillis=").append(draft.evaluatedAtEpochMillis).append('\n')
        append("authorizationExpiresAtEpochMillis=").append(draft.authorizationExpiresAtEpochMillis).append('\n')
        append("blockers=").append(
            draft.blockers.joinToString("|") { "${it.code}:${it.detail}" },
        ).append('\n')
        append("approvalChallengeSha256=").append(draft.approvalChallengeSha256).append('\n')
    }

    private fun safeAdd(left: Long, right: Long): Long =
        if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "SSH-session authorization hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

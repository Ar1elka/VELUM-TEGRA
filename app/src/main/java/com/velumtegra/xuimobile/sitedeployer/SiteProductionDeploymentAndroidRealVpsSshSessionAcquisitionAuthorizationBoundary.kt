package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import java.security.MessageDigest

/**
 * Phase 11.42 non-network real-VPS SSH-session-acquisition authorization boundary.
 *
 * It binds the exact successful Phase 11.41 credential-resolution proof and untouched ephemeral
 * credential-lease metadata to the exact reviewed public ServerAccess, canonical host-key pin and
 * JschSshConnectionFactory/ExactSessionRegistry implementation identities. Explicit approval only
 * authorizes one future durable handoff. This boundary never reads lease material, never touches
 * production network, never verifies the host key against a remote peer, and never opens SSH/SFTP.
 */
internal object SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 15_000L

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        resolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft {
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
            .validateProof(resolutionProof)
        require(
            resolutionProof.status ==
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus
                    .RESOLVED_TO_EPHEMERAL_LEASE,
        ) { "Only a successfully resolved real-VPS credential may enter SSH-session authorization" }
        require(resolutionProof.requiresSeparateSshSessionAcquisitionBoundary) {
            "Phase 11.41 proof does not require this SSH-session boundary"
        }
        require(resolutionProof.requiresLiveRemoteHostKeyVerification) {
            "Real-VPS SSH-session authorization must preserve live host-key verification"
        }
        require(serverAccess.id.value == resolutionProof.serverAccessId) {
            "Real-VPS SSH-session authorization ServerAccess mismatch"
        }
        require(credentialLease.serverAccessId == resolutionProof.serverAccessId) {
            "Real-VPS SSH-session authorization credential lease ServerAccess mismatch"
        }
        require(credentialLease.secretReferenceType == resolutionProof.secretReferenceType) {
            "Real-VPS SSH-session authorization credential lease auth type mismatch"
        }
        require(credentialLease.secretReferenceSha256 == resolutionProof.secretReferenceSha256) {
            "Real-VPS SSH-session authorization credential lease SecretId hash mismatch"
        }
        require(
            credentialLease.credentialResolutionConsumptionReceiptSha256 ==
                resolutionProof.credentialResolutionConsumptionReceiptSha256,
        ) { "Real-VPS SSH-session authorization credential lease receipt mismatch" }
        require(credentialLease.resolvedAtEpochMillis == resolutionProof.resolvedAtEpochMillis) {
            "Real-VPS SSH-session authorization credential lease resolution time mismatch"
        }
        require(
            credentialLease.authorizationExpiresAtEpochMillis ==
                resolutionProof.authorizationExpiresAtEpochMillis,
        ) { "Real-VPS SSH-session authorization credential lease expiry mismatch" }
        require(canonicalId.matches(authorizationAttemptId)) {
            "Real-VPS SSH-session authorization attempt id must be a canonical 8..128 character identifier"
        }
        require(evaluatedAtEpochMillis >= resolutionProof.resolvedAtEpochMillis) {
            "Real-VPS SSH-session authorization cannot predate credential resolution"
        }
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "Real-VPS SSH-session authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == resolutionProof.secretReferenceType) {
            "Real-VPS SSH-session authorization authentication reference type drifted"
        }
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        require(secretReferenceSha256 == resolutionProof.secretReferenceSha256) {
            "Real-VPS SSH-session authorization SecretId reference drifted"
        }
        val pinnedHostKeySha256 = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }
        val bindingSha256 = serverAccessBindingSha256(
            serverAccess = serverAccess,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            pinnedHostKeySha256 = pinnedHostKeySha256,
        )
        require(bindingSha256 == resolutionProof.serverAccessBindingSha256) {
            "Real-VPS SSH-session authorization ServerAccess binding drifted after Phase 11.41"
        }
        require(resolutionProof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name) {
            "Real-VPS SSH-session authorization is bound to an unexpected credential store"
        }

        val requestedExpiry = safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis)
        val authorizationExpiresAt = minOf(
            requestedExpiry,
            resolutionProof.authorizationExpiresAtEpochMillis,
        )
        val blockers = buildList {
            if (evaluatedAtEpochMillis > resolutionProof.authorizationExpiresAtEpochMillis) {
                add(
                    SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationBlocker(
                        code = "CREDENTIAL_WINDOW_EXPIRED",
                        detail = "Phase 11.41 credential authorization window expired before SSH-session authorization",
                    ),
                )
            }
            if (authorizationExpiresAt <= evaluatedAtEpochMillis) {
                add(
                    SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationBlocker(
                        code = "NO_SAFE_SSH_SESSION_AUTHORIZATION_WINDOW",
                        detail = "No positive real-VPS SSH-session authorization window remains",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus
                .AWAITING_EXPLICIT_SSH_SESSION_ACQUISITION_APPROVAL
        } else {
            SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus.BLOCKED
        }

        val base = SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesSshSessionAcquisition = false,
            authorizesSingleSshSessionAcquisitionHandoff = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeSshSessionAcquisition = true,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateSshSessionAcquisitionExecutionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            resolutionProofSha256 = resolutionProof.resolutionProofSha256,
            credentialResolutionConsumptionReceiptSha256 =
                resolutionProof.credentialResolutionConsumptionReceiptSha256,
            serverAccessBindingSha256 = resolutionProof.serverAccessBindingSha256,
            requestSha256 = resolutionProof.requestSha256,
            capabilityProfileSha256 = resolutionProof.capabilityProfileSha256,
            serverAccessId = resolutionProof.serverAccessId,
            remoteHostIdentity = serverAccess.endpoint.host,
            remotePort = serverAccess.endpoint.port,
            username = serverAccess.username,
            pinnedHostKeySha256 = pinnedHostKeySha256,
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
        draft: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsSshSessionAcquisitionApproval,
    ): SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization {
        validateDraft(draft)
        require(
            draft.status ==
                SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus
                    .AWAITING_EXPLICIT_SSH_SESSION_ACQUISITION_APPROVAL,
        ) { "Blocked real-VPS SSH-session authorization draft cannot be approved" }
        require(approval.confirmed) {
            "Real-VPS SSH-session acquisition handoff requires explicit confirmation"
        }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "Real-VPS SSH-session acquisition approval is stale or bound to a different draft"
        }

        val base = SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_SSH_SESSION_ACQUISITION_HANDOFF,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesSshSessionAcquisition = false,
            authorizesSingleSshSessionAcquisitionHandoff = true,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeSshSessionAcquisition = true,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateSshSessionAcquisitionExecutionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            resolutionProofSha256 = draft.resolutionProofSha256,
            credentialResolutionConsumptionReceiptSha256 =
                draft.credentialResolutionConsumptionReceiptSha256,
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
            credentialStoreImplementation = draft.credentialStoreImplementation,
            sshConnectionFactoryImplementation = draft.sshConnectionFactoryImplementation,
            exactSessionRegistryImplementation = draft.exactSessionRegistryImplementation,
            authorizationAttemptId = draft.authorizationAttemptId,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            approvalChallengeSha256 = draft.approvalChallengeSha256,
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base)).also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION)
        require(draft.authorizationOnly)
        validateNonExecutionFlags(
            draft.credentialLeaseMaterialRead,
            draft.productionNetworkTouched,
            draft.hostKeyPinVerifiedAgainstRemote,
            draft.authorizesNetworkAccess,
            draft.authorizesSshSessionAcquisition,
            draft.authorizesSingleSshSessionAcquisitionHandoff,
            draft.authorizesSftpChannelOpen,
            draft.authorizesReadOnlyPreflightExecution,
            draft.authorizesMutation,
            draft.authorizesCoordinatorInvocation,
            draft.exposesDeployUiAction,
            draft.realVpsAccessAllowed,
            allowHandoff = false,
        )
        require(draft.requiresExplicitApproval)
        validateRequiredSeparation(draft)
        require(canonicalId.matches(draft.authorizationAttemptId))
        require(draft.remoteHostIdentity.isNotBlank())
        require(draft.remotePort in 1..65535)
        require(draft.username.isNotBlank())
        require(draft.secretReferenceType == "password" || draft.secretReferenceType == "private-key")
        require(draft.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(draft.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(draft.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        val expectedStatus = if (draft.blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus
                .AWAITING_EXPLICIT_SSH_SESSION_ACQUISITION_APPROVAL
        } else {
            SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus.BLOCKED
        }
        require(draft.status == expectedStatus)
        if (draft.blockers.isEmpty()) require(draft.authorizationExpiresAtEpochMillis > draft.evaluatedAtEpochMillis)
        validateHashes(
            draft.resolutionProofSha256,
            draft.credentialResolutionConsumptionReceiptSha256,
            draft.serverAccessBindingSha256,
            draft.requestSha256,
            draft.capabilityProfileSha256,
            draft.pinnedHostKeySha256,
            draft.secretReferenceSha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = ""))) {
            "Real-VPS SSH-session authorization draft SHA-256 mismatch"
        }
    }

    fun validateAuthorization(
        authorization: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization,
    ) {
        require(authorization.contractVersion == CONTRACT_VERSION)
        require(
            authorization.status ==
                SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationStatus
                    .AUTHORIZED_FOR_SINGLE_SSH_SESSION_ACQUISITION_HANDOFF,
        )
        require(authorization.authorizationOnly)
        validateNonExecutionFlags(
            authorization.credentialLeaseMaterialRead,
            authorization.productionNetworkTouched,
            authorization.hostKeyPinVerifiedAgainstRemote,
            authorization.authorizesNetworkAccess,
            authorization.authorizesSshSessionAcquisition,
            authorization.authorizesSingleSshSessionAcquisitionHandoff,
            authorization.authorizesSftpChannelOpen,
            authorization.authorizesReadOnlyPreflightExecution,
            authorization.authorizesMutation,
            authorization.authorizesCoordinatorInvocation,
            authorization.exposesDeployUiAction,
            authorization.realVpsAccessAllowed,
            allowHandoff = true,
        )
        require(authorization.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition)
        require(authorization.requiresLiveRemoteHostKeyVerification)
        require(authorization.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        require(authorization.requiresSeparateSftpChannelOpenBoundary)
        require(authorization.requiresSeparateReadOnlyExecutionBoundary)
        require(authorization.requiresSeparateMutationBoundary)
        require(authorization.authorizationExpiresAtEpochMillis > authorization.evaluatedAtEpochMillis)
        require(authorization.remoteHostIdentity.isNotBlank())
        require(authorization.remotePort in 1..65535)
        require(authorization.username.isNotBlank())
        require(authorization.secretReferenceType == "password" || authorization.secretReferenceType == "private-key")
        require(authorization.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(authorization.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(authorization.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        validateHashes(
            authorization.resolutionProofSha256,
            authorization.credentialResolutionConsumptionReceiptSha256,
            authorization.serverAccessBindingSha256,
            authorization.requestSha256,
            authorization.capabilityProfileSha256,
            authorization.pinnedHostKeySha256,
            authorization.secretReferenceSha256,
            authorization.approvalChallengeSha256,
            authorization.authorizationSha256,
        )
        require(
            authorization.authorizationSha256 ==
                authorizationSha256(authorization.copy(authorizationSha256 = "")),
        ) { "Real-VPS SSH-session acquisition authorization SHA-256 mismatch" }
    }

    private fun validateNonExecutionFlags(
        credentialLeaseMaterialRead: Boolean,
        productionNetworkTouched: Boolean,
        hostKeyPinVerifiedAgainstRemote: Boolean,
        authorizesNetworkAccess: Boolean,
        authorizesSshSessionAcquisition: Boolean,
        authorizesSingleSshSessionAcquisitionHandoff: Boolean,
        authorizesSftpChannelOpen: Boolean,
        authorizesReadOnlyPreflightExecution: Boolean,
        authorizesMutation: Boolean,
        authorizesCoordinatorInvocation: Boolean,
        exposesDeployUiAction: Boolean,
        realVpsAccessAllowed: Boolean,
        allowHandoff: Boolean,
    ) {
        require(!credentialLeaseMaterialRead)
        require(!productionNetworkTouched)
        require(!hostKeyPinVerifiedAgainstRemote)
        require(!authorizesNetworkAccess)
        require(!authorizesSshSessionAcquisition)
        require(authorizesSingleSshSessionAcquisitionHandoff == allowHandoff)
        require(!authorizesSftpChannelOpen)
        require(!authorizesReadOnlyPreflightExecution)
        require(!authorizesMutation)
        require(!authorizesCoordinatorInvocation)
        require(!exposesDeployUiAction)
        require(!realVpsAccessAllowed)
    }

    private fun validateRequiredSeparation(
        draft: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft,
    ) {
        require(draft.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition)
        require(draft.requiresLiveRemoteHostKeyVerification)
        require(draft.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        require(draft.requiresSeparateSftpChannelOpenBoundary)
        require(draft.requiresSeparateReadOnlyExecutionBoundary)
        require(draft.requiresSeparateMutationBoundary)
    }

    private fun secretReferenceSha256(
        serverAccessId: String,
        secretReferenceType: String,
        secretIdValue: String,
    ): String = sha256(
        buildString {
            append("serverAccessId=").append(serverAccessId).append('\n')
            append("secretReferenceType=").append(secretReferenceType).append('\n')
            append("secretId=").append(secretIdValue).append('\n')
        },
    )

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        secretReferenceType: String,
        secretReferenceSha256: String,
        pinnedHostKeySha256: String,
    ): String = sha256(
        buildString {
            append("serverAccessId=").append(serverAccess.id.value).append('\n')
            append("serverId=").append(serverAccess.serverId.value).append('\n')
            append("host=").append(serverAccess.endpoint.host).append('\n')
            append("port=").append(serverAccess.endpoint.port).append('\n')
            append("username=").append(serverAccess.username).append('\n')
            append("secretReferenceType=").append(secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
            append("pinnedHostKeySha256=").append(pinnedHostKeySha256).append('\n')
        },
    )

    private fun approvalChallengeSha256(
        draft: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft,
    ): String = sha256(
        "real-vps-ssh-session-acquisition-approval\n" + canonicalDraft(
            draft.copy(approvalChallengeSha256 = "", draftSha256 = ""),
        ),
    )

    private fun draftSha256(
        draft: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft,
    ): String = sha256(canonicalDraft(draft.copy(draftSha256 = "")))

    private fun authorizationSha256(
        authorization: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization,
    ): String = sha256(
        buildString {
            append("phase=11.42\n")
            append("contractVersion=").append(authorization.contractVersion).append('\n')
            append("status=").append(authorization.status.name).append('\n')
            appendCommon(
                resolutionProofSha256 = authorization.resolutionProofSha256,
                credentialResolutionConsumptionReceiptSha256 =
                    authorization.credentialResolutionConsumptionReceiptSha256,
                serverAccessBindingSha256 = authorization.serverAccessBindingSha256,
                requestSha256 = authorization.requestSha256,
                capabilityProfileSha256 = authorization.capabilityProfileSha256,
                serverAccessId = authorization.serverAccessId,
                remoteHostIdentity = authorization.remoteHostIdentity,
                remotePort = authorization.remotePort,
                username = authorization.username,
                pinnedHostKeySha256 = authorization.pinnedHostKeySha256,
                secretReferenceType = authorization.secretReferenceType,
                secretReferenceSha256 = authorization.secretReferenceSha256,
                credentialStoreImplementation = authorization.credentialStoreImplementation,
                sshConnectionFactoryImplementation = authorization.sshConnectionFactoryImplementation,
                exactSessionRegistryImplementation = authorization.exactSessionRegistryImplementation,
                authorizationAttemptId = authorization.authorizationAttemptId,
                evaluatedAtEpochMillis = authorization.evaluatedAtEpochMillis,
                authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            )
            append("approvalChallengeSha256=").append(authorization.approvalChallengeSha256).append('\n')
            append("authorizesSingleSshSessionAcquisitionHandoff=")
                .append(authorization.authorizesSingleSshSessionAcquisitionHandoff).append('\n')
        },
    )

    private fun canonicalDraft(
        draft: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft,
    ): String = buildString {
        append("phase=11.42\n")
        append("contractVersion=").append(draft.contractVersion).append('\n')
        append("status=").append(draft.status.name).append('\n')
        appendCommon(
            resolutionProofSha256 = draft.resolutionProofSha256,
            credentialResolutionConsumptionReceiptSha256 =
                draft.credentialResolutionConsumptionReceiptSha256,
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
            credentialStoreImplementation = draft.credentialStoreImplementation,
            sshConnectionFactoryImplementation = draft.sshConnectionFactoryImplementation,
            exactSessionRegistryImplementation = draft.exactSessionRegistryImplementation,
            authorizationAttemptId = draft.authorizationAttemptId,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
        )
        append("blockers=").append(draft.blockers.joinToString("|") { "${it.code}:${it.detail}" }).append('\n')
        append("approvalChallengeSha256=").append(draft.approvalChallengeSha256).append('\n')
    }

    private fun StringBuilder.appendCommon(
        resolutionProofSha256: String,
        credentialResolutionConsumptionReceiptSha256: String,
        serverAccessBindingSha256: String,
        requestSha256: String,
        capabilityProfileSha256: String,
        serverAccessId: String,
        remoteHostIdentity: String,
        remotePort: Int,
        username: String,
        pinnedHostKeySha256: String,
        secretReferenceType: String,
        secretReferenceSha256: String,
        credentialStoreImplementation: String,
        sshConnectionFactoryImplementation: String,
        exactSessionRegistryImplementation: String,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        authorizationExpiresAtEpochMillis: Long,
    ) {
        append("resolutionProofSha256=").append(resolutionProofSha256).append('\n')
        append("credentialResolutionConsumptionReceiptSha256=")
            .append(credentialResolutionConsumptionReceiptSha256).append('\n')
        append("serverAccessBindingSha256=").append(serverAccessBindingSha256).append('\n')
        append("requestSha256=").append(requestSha256).append('\n')
        append("capabilityProfileSha256=").append(capabilityProfileSha256).append('\n')
        append("serverAccessId=").append(serverAccessId).append('\n')
        append("remoteHostIdentity=").append(remoteHostIdentity).append('\n')
        append("remotePort=").append(remotePort).append('\n')
        append("username=").append(username).append('\n')
        append("pinnedHostKeySha256=").append(pinnedHostKeySha256).append('\n')
        append("secretReferenceType=").append(secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
        append("credentialStoreImplementation=").append(credentialStoreImplementation).append('\n')
        append("sshConnectionFactoryImplementation=").append(sshConnectionFactoryImplementation).append('\n')
        append("exactSessionRegistryImplementation=").append(exactSessionRegistryImplementation).append('\n')
        append("authorizationAttemptId=").append(authorizationAttemptId).append('\n')
        append("evaluatedAtEpochMillis=").append(evaluatedAtEpochMillis).append('\n')
        append("authorizationExpiresAtEpochMillis=").append(authorizationExpiresAtEpochMillis).append('\n')
    }

    private fun safeAdd(left: Long, right: Long): Long =
        if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS SSH-session authorization hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import java.security.MessageDigest

/**
 * Phase 11.48 non-network authorization for one future bounded real-VPS SFTP read-only preflight.
 *
 * The boundary accepts the exact Phase 11.38 preflight handoff receipt together with the exact
 * successful-and-closed Phase 11.47 SFTP channel-open proof. It binds the previously reviewed
 * target/staging/backup roots and bounded lstat/list vocabulary to fresh explicit approval.
 * Authorization itself performs no credential read, network access, SFTP operation or remote read.
 */
internal object SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 15_000L

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        sftpExecutionProof: SiteProductionDeploymentRealVpsSftpChannelOpenExecutionProof,
        preflightReceipt: SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft {
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenExecutionBoundary.validateProof(sftpExecutionProof)
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightHandoffConsumptionBoundary
            .validateReceipt(preflightReceipt)

        require(
            sftpExecutionProof.status ==
                SiteProductionDeploymentRealVpsSftpChannelOpenExecutionStatus
                    .REAL_VPS_SFTP_CHANNEL_OPENED_AND_CLOSED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
        ) { "Phase 11.48 requires the exact successful Phase 11.47 SFTP execution proof" }
        require(sftpExecutionProof.productionNetworkTouched)
        require(sftpExecutionProof.hostKeyPinVerifiedAgainstRemote)
        require(sftpExecutionProof.sftpChannelOpened && sftpExecutionProof.sftpChannelClosed)
        require(!sftpExecutionProof.sftpOperationPerformed)
        require(!sftpExecutionProof.remoteCommandDispatched)
        require(!sftpExecutionProof.remoteReadPerformed)
        require(!sftpExecutionProof.mutationPerformed)
        require(sftpExecutionProof.sessionClosed)
        require(sftpExecutionProof.requiresSeparateReadOnlyExecutionBoundary)

        require(preflightReceipt.singleUseConsumed)
        require(!preflightReceipt.productionNetworkTouched)
        require(!preflightReceipt.credentialLeaseMaterialRead)
        require(preflightReceipt.requiresSeparateReadOnlyExecutionBoundary)
        require(!preflightReceipt.authorizesReadOnlyPreflightExecution)
        require(!preflightReceipt.authorizesMutation)

        require(canonicalId.matches(authorizationAttemptId)) {
            "Real-VPS read-only preflight authorization attempt id must be canonical"
        }
        require(evaluatedAtEpochMillis >= sftpExecutionProof.executedAtEpochMillis) {
            "Phase 11.48 authorization cannot predate the Phase 11.47 proof"
        }
        require(evaluatedAtEpochMillis >= preflightReceipt.consumedAtEpochMillis) {
            "Phase 11.48 authorization cannot predate the Phase 11.38 preflight handoff"
        }
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "Phase 11.48 authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }

        require(serverAccess.id.value == sftpExecutionProof.serverAccessId)
        require(serverAccess.id.value == preflightReceipt.serverAccessId)
        require(serverAccess.endpoint.host == sftpExecutionProof.remoteHostIdentity)
        require(serverAccess.endpoint.host == preflightReceipt.remoteHostIdentity)
        require(serverAccess.endpoint.port == sftpExecutionProof.remotePort)
        require(serverAccess.endpoint.port == preflightReceipt.remotePort)
        require(serverAccess.username == sftpExecutionProof.username)
        require(!isLoopbackHost(serverAccess.endpoint.host)) {
            "Phase 11.48 requires the exact reviewed non-loopback real-VPS endpoint"
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == sftpExecutionProof.secretReferenceType)
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        require(secretReferenceSha256 == sftpExecutionProof.secretReferenceSha256)

        val pinnedHostKeySha256 = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }
        require(pinnedHostKeySha256 == sftpExecutionProof.pinnedHostKeySha256)
        require(pinnedHostKeySha256 == sftpExecutionProof.verifiedHostKeySha256)
        require(pinnedHostKeySha256 == preflightReceipt.pinnedHostKeySha256)

        require(sftpExecutionProof.serverAccessBindingSha256 == preflightReceipt.serverAccessBindingSha256) {
            "Phase 11.47 and Phase 11.38 ServerAccess bindings differ"
        }
        require(sftpExecutionProof.requestSha256 == preflightReceipt.requestSha256) {
            "Phase 11.47 and Phase 11.38 deployment requests differ"
        }
        require(sftpExecutionProof.capabilityProfileSha256 == preflightReceipt.capabilityProfileSha256) {
            "Phase 11.47 and Phase 11.38 capability profiles differ"
        }
        require(
            preflightReceipt.approvedReadOnlyOperationVocabulary ==
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
        ) { "Read-only operation vocabulary drifted" }
        require(preflightReceipt.maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(preflightReceipt.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        require(preflightReceipt.expectedTargetEntryNames.isNotEmpty())
        require(preflightReceipt.expectedTargetEntryNames == preflightReceipt.expectedTargetEntryNames.sorted())
        require(preflightReceipt.expectedTargetEntryNames.size <= preflightReceipt.maxTargetEntries)

        val requestedExpiry = safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis)
        val authorizationExpiresAt = minOf(requestedExpiry, preflightReceipt.authorizationExpiresAtEpochMillis)
        val blockers = buildList {
            if (authorizationExpiresAt <= evaluatedAtEpochMillis) {
                add(
                    SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationBlocker(
                        code = "REAL_VPS_READ_ONLY_PREFLIGHT_SOURCE_AUTHORIZATION_EXPIRED",
                        detail = "No positive Phase 11.38 read-only preflight authorization window remains",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus
                .AWAITING_EXPLICIT_READ_ONLY_PREFLIGHT_APPROVAL
        } else {
            SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus.BLOCKED
        }

        val base = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemoteByPriorProof = true,
            priorSftpChannelOpenedAndClosedWithoutOperation = true,
            authorizesNetworkAccess = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesSingleReadOnlyPreflightHandoff = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeReadOnlyPreflight = true,
            requiresFreshCredentialResolutionBeforeReadOnlyExecution = true,
            requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution = true,
            requiresFreshSftpChannelOpenBeforeReadOnlyExecution = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            priorSftpExecutionProofSha256 = sftpExecutionProof.executionProofSha256,
            priorSftpExecutionReceiptSha256 = sftpExecutionProof.sftpChannelOpenConsumptionReceiptSha256,
            preflightHandoffConsumptionReceiptSha256 = preflightReceipt.consumptionReceiptSha256,
            sourcePreflightAuthorizationSha256 = preflightReceipt.authorizationSha256,
            admissionSha256 = preflightReceipt.admissionSha256,
            serverAccessBindingSha256 = preflightReceipt.serverAccessBindingSha256,
            requestSha256 = preflightReceipt.requestSha256,
            capabilityProfileSha256 = preflightReceipt.capabilityProfileSha256,
            serverAccessId = preflightReceipt.serverAccessId,
            remoteHostIdentity = preflightReceipt.remoteHostIdentity,
            remotePort = preflightReceipt.remotePort,
            username = sftpExecutionProof.username,
            pinnedHostKeySha256 = preflightReceipt.pinnedHostKeySha256,
            secretReferenceType = sftpExecutionProof.secretReferenceType,
            secretReferenceSha256 = sftpExecutionProof.secretReferenceSha256,
            targetRoot = preflightReceipt.targetRoot,
            stagingRoot = preflightReceipt.stagingRoot,
            backupRoot = preflightReceipt.backupRoot,
            expectedTargetEntryNames = preflightReceipt.expectedTargetEntryNames,
            approvedReadOnlyOperationVocabulary = preflightReceipt.approvedReadOnlyOperationVocabulary,
            maxTargetEntries = preflightReceipt.maxTargetEntries,
            sftpReadOnlyProbeImplementation = preflightReceipt.sftpReadOnlyProbeImplementation,
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
        draft: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightApproval,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization {
        validateDraft(draft)
        require(
            draft.status == SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus
                .AWAITING_EXPLICIT_READ_ONLY_PREFLIGHT_APPROVAL,
        ) { "Blocked real-VPS read-only preflight authorization cannot be approved" }
        require(approval.confirmed) { "Real-VPS read-only preflight handoff requires explicit confirmation" }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "Real-VPS read-only preflight approval is stale or bound to another draft"
        }
        val base = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization(
            contractVersion = draft.contractVersion,
            status = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_READ_ONLY_PREFLIGHT_HANDOFF,
            authorizationOnly = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemoteByPriorProof = true,
            priorSftpChannelOpenedAndClosedWithoutOperation = true,
            authorizesNetworkAccess = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesSingleReadOnlyPreflightHandoff = true,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeReadOnlyPreflight = true,
            requiresFreshCredentialResolutionBeforeReadOnlyExecution = true,
            requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution = true,
            requiresFreshSftpChannelOpenBeforeReadOnlyExecution = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            priorSftpExecutionProofSha256 = draft.priorSftpExecutionProofSha256,
            priorSftpExecutionReceiptSha256 = draft.priorSftpExecutionReceiptSha256,
            preflightHandoffConsumptionReceiptSha256 = draft.preflightHandoffConsumptionReceiptSha256,
            sourcePreflightAuthorizationSha256 = draft.sourcePreflightAuthorizationSha256,
            admissionSha256 = draft.admissionSha256,
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
            targetRoot = draft.targetRoot,
            stagingRoot = draft.stagingRoot,
            backupRoot = draft.backupRoot,
            expectedTargetEntryNames = draft.expectedTargetEntryNames,
            approvedReadOnlyOperationVocabulary = draft.approvedReadOnlyOperationVocabulary,
            maxTargetEntries = draft.maxTargetEntries,
            sftpReadOnlyProbeImplementation = draft.sftpReadOnlyProbeImplementation,
            authorizationAttemptId = draft.authorizationAttemptId,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            approvalChallengeSha256 = draft.approvalChallengeSha256,
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base)).also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION)
        require(draft.authorizationOnly)
        require(!draft.credentialLeaseMaterialRead)
        require(!draft.productionNetworkTouched)
        require(draft.hostKeyPinVerifiedAgainstRemoteByPriorProof)
        require(draft.priorSftpChannelOpenedAndClosedWithoutOperation)
        require(!draft.authorizesNetworkAccess)
        require(!draft.authorizesReadOnlyPreflightExecution)
        require(!draft.authorizesSingleReadOnlyPreflightHandoff)
        require(!draft.authorizesMutation)
        require(!draft.authorizesCoordinatorInvocation)
        require(!draft.exposesDeployUiAction)
        require(!draft.realVpsAccessAllowed)
        require(draft.requiresExplicitApproval)
        require(draft.requiresDurableOneShotConsumptionBeforeReadOnlyPreflight)
        require(draft.requiresFreshCredentialResolutionBeforeReadOnlyExecution)
        require(draft.requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution)
        require(draft.requiresFreshSftpChannelOpenBeforeReadOnlyExecution)
        require(draft.requiresSeparateReadOnlyExecutionBoundary)
        require(draft.requiresSeparateMutationBoundary)
        require(!isLoopbackHost(draft.remoteHostIdentity))
        require(draft.remotePort in 1..65535)
        require(draft.username.isNotBlank())
        require(draft.expectedTargetEntryNames.isNotEmpty())
        require(draft.expectedTargetEntryNames == draft.expectedTargetEntryNames.sorted())
        require(draft.expectedTargetEntryNames.size <= draft.maxTargetEntries)
        require(
            draft.approvedReadOnlyOperationVocabulary ==
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
        )
        require(draft.maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(draft.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        if (draft.status == SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus.BLOCKED) {
            require(draft.blockers.isNotEmpty())
            require(draft.authorizationExpiresAtEpochMillis <= draft.evaluatedAtEpochMillis)
        } else {
            require(
                draft.status == SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus
                    .AWAITING_EXPLICIT_READ_ONLY_PREFLIGHT_APPROVAL,
            )
            require(draft.blockers.isEmpty())
            require(draft.authorizationExpiresAtEpochMillis > draft.evaluatedAtEpochMillis)
        }
        validateHashes(
            draft.priorSftpExecutionProofSha256,
            draft.priorSftpExecutionReceiptSha256,
            draft.preflightHandoffConsumptionReceiptSha256,
            draft.sourcePreflightAuthorizationSha256,
            draft.admissionSha256,
            draft.serverAccessBindingSha256,
            draft.requestSha256,
            draft.capabilityProfileSha256,
            draft.pinnedHostKeySha256,
            draft.secretReferenceSha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(
            draft.approvalChallengeSha256 == approvalChallengeSha256(
                draft.copy(approvalChallengeSha256 = "", draftSha256 = ""),
            ),
        )
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = "")))
    }

    fun validateAuthorization(
        authorization: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization,
    ) {
        require(authorization.contractVersion == CONTRACT_VERSION)
        require(
            authorization.status == SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_READ_ONLY_PREFLIGHT_HANDOFF,
        )
        require(authorization.authorizationOnly)
        require(!authorization.credentialLeaseMaterialRead)
        require(!authorization.productionNetworkTouched)
        require(authorization.hostKeyPinVerifiedAgainstRemoteByPriorProof)
        require(authorization.priorSftpChannelOpenedAndClosedWithoutOperation)
        require(!authorization.authorizesNetworkAccess)
        require(!authorization.authorizesReadOnlyPreflightExecution)
        require(authorization.authorizesSingleReadOnlyPreflightHandoff)
        require(!authorization.authorizesMutation)
        require(!authorization.authorizesCoordinatorInvocation)
        require(!authorization.exposesDeployUiAction)
        require(!authorization.realVpsAccessAllowed)
        require(authorization.requiresDurableOneShotConsumptionBeforeReadOnlyPreflight)
        require(authorization.requiresFreshCredentialResolutionBeforeReadOnlyExecution)
        require(authorization.requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution)
        require(authorization.requiresFreshSftpChannelOpenBeforeReadOnlyExecution)
        require(authorization.requiresSeparateReadOnlyExecutionBoundary)
        require(authorization.requiresSeparateMutationBoundary)
        require(!isLoopbackHost(authorization.remoteHostIdentity))
        require(authorization.remotePort in 1..65535)
        require(authorization.authorizationExpiresAtEpochMillis > authorization.evaluatedAtEpochMillis)
        require(authorization.expectedTargetEntryNames.isNotEmpty())
        require(authorization.expectedTargetEntryNames == authorization.expectedTargetEntryNames.sorted())
        require(authorization.expectedTargetEntryNames.size <= authorization.maxTargetEntries)
        require(
            authorization.approvedReadOnlyOperationVocabulary ==
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
        )
        require(authorization.maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(authorization.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        validateHashes(
            authorization.priorSftpExecutionProofSha256,
            authorization.priorSftpExecutionReceiptSha256,
            authorization.preflightHandoffConsumptionReceiptSha256,
            authorization.sourcePreflightAuthorizationSha256,
            authorization.admissionSha256,
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
        ) { "Phase 11.48 authorization SHA-256 mismatch" }
    }

    private fun approvalChallengeSha256(
        draft: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft,
    ): String = sha256(buildString {
        append("phase=11.48\n")
        append("purpose=real-vps-sftp-read-only-preflight-approval\n")
        append("priorSftpExecutionProofSha256=").append(draft.priorSftpExecutionProofSha256).append('\n')
        append("preflightHandoffConsumptionReceiptSha256=")
            .append(draft.preflightHandoffConsumptionReceiptSha256).append('\n')
        append("requestSha256=").append(draft.requestSha256).append('\n')
        append("targetRoot=").append(draft.targetRoot).append('\n')
        append("stagingRoot=").append(draft.stagingRoot).append('\n')
        append("backupRoot=").append(draft.backupRoot).append('\n')
        append("expected=").append(draft.expectedTargetEntryNames.joinToString(",")).append('\n')
        append("ops=").append(draft.approvedReadOnlyOperationVocabulary.joinToString(",")).append('\n')
        append("attemptId=").append(draft.authorizationAttemptId).append('\n')
        append("evaluatedAt=").append(draft.evaluatedAtEpochMillis).append('\n')
        append("expiresAt=").append(draft.authorizationExpiresAtEpochMillis).append('\n')
    })

    private fun draftSha256(
        draft: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft,
    ): String = sha256(buildString {
        append("phase=11.48\n")
        append("status=").append(draft.status.name).append('\n')
        append("priorSftpExecutionProofSha256=").append(draft.priorSftpExecutionProofSha256).append('\n')
        append("priorSftpExecutionReceiptSha256=").append(draft.priorSftpExecutionReceiptSha256).append('\n')
        append("preflightHandoffConsumptionReceiptSha256=").append(draft.preflightHandoffConsumptionReceiptSha256).append('\n')
        append("sourcePreflightAuthorizationSha256=").append(draft.sourcePreflightAuthorizationSha256).append('\n')
        append("admissionSha256=").append(draft.admissionSha256).append('\n')
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
        append("targetRoot=").append(draft.targetRoot).append('\n')
        append("stagingRoot=").append(draft.stagingRoot).append('\n')
        append("backupRoot=").append(draft.backupRoot).append('\n')
        append("expected=").append(draft.expectedTargetEntryNames.joinToString(",")).append('\n')
        append("ops=").append(draft.approvedReadOnlyOperationVocabulary.joinToString(",")).append('\n')
        append("maxTargetEntries=").append(draft.maxTargetEntries).append('\n')
        append("probe=").append(draft.sftpReadOnlyProbeImplementation).append('\n')
        append("attemptId=").append(draft.authorizationAttemptId).append('\n')
        append("evaluatedAt=").append(draft.evaluatedAtEpochMillis).append('\n')
        append("expiresAt=").append(draft.authorizationExpiresAtEpochMillis).append('\n')
        append("approvalChallengeSha256=").append(draft.approvalChallengeSha256).append('\n')
    })

    private fun authorizationSha256(
        authorization: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization,
    ): String = sha256(buildString {
        append("phase=11.48\n")
        append("status=").append(authorization.status.name).append('\n')
        append("priorSftpExecutionProofSha256=").append(authorization.priorSftpExecutionProofSha256).append('\n')
        append("priorSftpExecutionReceiptSha256=").append(authorization.priorSftpExecutionReceiptSha256).append('\n')
        append("preflightHandoffConsumptionReceiptSha256=").append(authorization.preflightHandoffConsumptionReceiptSha256).append('\n')
        append("sourcePreflightAuthorizationSha256=").append(authorization.sourcePreflightAuthorizationSha256).append('\n')
        append("admissionSha256=").append(authorization.admissionSha256).append('\n')
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
        append("targetRoot=").append(authorization.targetRoot).append('\n')
        append("stagingRoot=").append(authorization.stagingRoot).append('\n')
        append("backupRoot=").append(authorization.backupRoot).append('\n')
        append("expected=").append(authorization.expectedTargetEntryNames.joinToString(",")).append('\n')
        append("ops=").append(authorization.approvedReadOnlyOperationVocabulary.joinToString(",")).append('\n')
        append("maxTargetEntries=").append(authorization.maxTargetEntries).append('\n')
        append("probe=").append(authorization.sftpReadOnlyProbeImplementation).append('\n')
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

    private fun validateHashes(vararg values: String) {
        values.forEach { require(sha256Pattern.matches(it)) { "Expected lowercase SHA-256 binding" } }
    }

    private fun safeAdd(value: Long, delta: Long): Long = Math.addExact(value, delta)

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.trim().lowercase()
        return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1" ||
            normalized.startsWith("127.")
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}

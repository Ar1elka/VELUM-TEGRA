package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import java.security.MessageDigest

/**
 * Phase 11.37 explicit authorization for one exact Phase 11.36 real-VPS read-only preflight admission.
 *
 * This boundary is deliberately non-network. Approval authorizes only one future durable handoff.
 * It does not read credential material, verify a live host key, connect SSH, open SFTP, execute
 * any remote read, mutate remote state, invoke the coordinator, expose deploy UI, or access a VPS.
 */
internal object SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 15_000L

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        admission: SiteProductionDeploymentRealVpsReadOnlyPreflightAdmission,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft {
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary.validate(admission)
        require(canonicalId.matches(authorizationAttemptId)) {
            "Real-VPS read-only preflight authorization attempt id is not canonical"
        }
        require(evaluatedAtEpochMillis >= admission.evaluatedAtEpochMillis) {
            "Real-VPS read-only preflight authorization cannot predate admission"
        }
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "Real-VPS read-only preflight authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }

        val expiresAt = safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis)
        val blockers = buildList {
            if (
                admission.status !=
                SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus
                    .ADMITTED_FOR_SEPARATE_EXPLICIT_READ_ONLY_PREFLIGHT_AUTHORIZATION
            ) {
                add(
                    SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationBlocker(
                        code = "PHASE11_36_ADMISSION_NOT_ELIGIBLE",
                        detail = "Only an admitted Phase 11.36 non-loopback binding may request explicit authorization",
                    ),
                )
            }
            if (!admission.candidateEndpointIsNonLoopback) {
                add(
                    SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationBlocker(
                        code = "REAL_VPS_ENDPOINT_NOT_NON_LOOPBACK",
                        detail = "Explicit real-VPS authorization requires the admitted non-loopback endpoint",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus
                .AWAITING_EXPLICIT_REAL_VPS_READ_ONLY_PREFLIGHT_APPROVAL
        } else {
            SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus.BLOCKED
        }

        val base = SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            authorizationOnly = true,
            productionNetworkTouched = false,
            credentialLeaseMaterialRead = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesSingleRealVpsReadOnlyPreflightHandoff = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeAnyNetworkAccess = true,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateCredentialResolutionBoundary = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            admissionSha256 = admission.admissionSha256,
            serverAccessBindingSha256 = admission.serverAccessBindingSha256,
            requestSha256 = admission.requestSha256,
            capabilityProfileSha256 = admission.capabilityProfileSha256,
            serverAccessId = admission.serverAccessId,
            remoteHostIdentity = admission.remoteHostIdentity,
            remotePort = admission.remotePort,
            pinnedHostKeySha256 = admission.pinnedHostKeySha256,
            targetRoot = admission.targetRoot,
            stagingRoot = admission.stagingRoot,
            backupRoot = admission.backupRoot,
            expectedTargetEntryNames = admission.expectedTargetEntryNames,
            approvedReadOnlyOperationVocabulary = admission.approvedReadOnlyOperationVocabulary,
            maxTargetEntries = admission.maxTargetEntries,
            sftpReadOnlyProbeImplementation = admission.sftpReadOnlyProbeImplementation,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = expiresAt,
            blockers = blockers,
            approvalChallengeSha256 = "",
            draftSha256 = "",
        )
        val challenge = approvalChallengeSha256(base)
        val withChallenge = base.copy(approvalChallengeSha256 = challenge)
        return withChallenge.copy(draftSha256 = draftSha256(withChallenge)).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsReadOnlyPreflightApproval,
    ): SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorization {
        validateDraft(draft)
        require(
            draft.status ==
                SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus
                    .AWAITING_EXPLICIT_REAL_VPS_READ_ONLY_PREFLIGHT_APPROVAL,
        ) { "Blocked real-VPS read-only preflight authorization draft cannot be approved" }
        require(approval.confirmed) {
            "Real-VPS read-only preflight handoff requires explicit confirmation"
        }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "Real-VPS read-only preflight approval is stale or bound to a different draft"
        }

        val base = SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            contractVersion = draft.contractVersion,
            status = SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF,
            authorizationOnly = true,
            productionNetworkTouched = false,
            credentialLeaseMaterialRead = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesSingleRealVpsReadOnlyPreflightHandoff = true,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeAnyNetworkAccess = true,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateCredentialResolutionBoundary = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            admissionSha256 = draft.admissionSha256,
            serverAccessBindingSha256 = draft.serverAccessBindingSha256,
            requestSha256 = draft.requestSha256,
            capabilityProfileSha256 = draft.capabilityProfileSha256,
            serverAccessId = draft.serverAccessId,
            remoteHostIdentity = draft.remoteHostIdentity,
            remotePort = draft.remotePort,
            pinnedHostKeySha256 = draft.pinnedHostKeySha256,
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
        return base.copy(authorizationSha256 = authorizationSha256(base))
            .also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION)
        require(draft.authorizationOnly)
        validateNonNetworkFlags(
            productionNetworkTouched = draft.productionNetworkTouched,
            credentialLeaseMaterialRead = draft.credentialLeaseMaterialRead,
            hostKeyPinVerifiedAgainstRemote = draft.hostKeyPinVerifiedAgainstRemote,
            authorizesNetworkAccess = draft.authorizesNetworkAccess,
            authorizesCredentialResolution = draft.authorizesCredentialResolution,
            authorizesSshSessionAcquisition = draft.authorizesSshSessionAcquisition,
            authorizesSftpChannelOpen = draft.authorizesSftpChannelOpen,
            authorizesReadOnlyPreflightExecution = draft.authorizesReadOnlyPreflightExecution,
            authorizesMutation = draft.authorizesMutation,
            authorizesCoordinatorInvocation = draft.authorizesCoordinatorInvocation,
            exposesDeployUiAction = draft.exposesDeployUiAction,
            realVpsAccessAllowed = draft.realVpsAccessAllowed,
        )
        require(!draft.authorizesSingleRealVpsReadOnlyPreflightHandoff)
        require(draft.requiresExplicitApproval)
        validateRequiredSeparation(
            durableConsumption = draft.requiresDurableOneShotConsumptionBeforeAnyNetworkAccess,
            liveHostKeyVerification = draft.requiresLiveRemoteHostKeyVerification,
            credentialResolution = draft.requiresSeparateCredentialResolutionBoundary,
            sshSession = draft.requiresSeparateSshSessionAcquisitionBoundary,
            sftpChannel = draft.requiresSeparateSftpChannelOpenBoundary,
            readOnlyExecution = draft.requiresSeparateReadOnlyExecutionBoundary,
            mutation = draft.requiresSeparateMutationBoundary,
        )
        validateBoundProfile(
            vocabulary = draft.approvedReadOnlyOperationVocabulary,
            maxTargetEntries = draft.maxTargetEntries,
            probeImplementation = draft.sftpReadOnlyProbeImplementation,
        )
        require(draft.remotePort in 1..65535)
        require(draft.evaluatedAtEpochMillis >= 0L)
        require(draft.authorizationExpiresAtEpochMillis > draft.evaluatedAtEpochMillis)
        require(canonicalId.matches(draft.authorizationAttemptId))
        val expectedStatus = if (draft.blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus
                .AWAITING_EXPLICIT_REAL_VPS_READ_ONLY_PREFLIGHT_APPROVAL
        } else {
            SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus.BLOCKED
        }
        require(draft.status == expectedStatus)
        validateHashes(
            draft.admissionSha256,
            draft.serverAccessBindingSha256,
            draft.requestSha256,
            draft.capabilityProfileSha256,
            draft.pinnedHostKeySha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(draft.approvalChallengeSha256 == approvalChallengeSha256(draft.copy(
            approvalChallengeSha256 = "",
            draftSha256 = "",
        )))
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = "")))
    }

    fun validateAuthorization(
        authorization: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorization,
    ) {
        require(authorization.contractVersion == CONTRACT_VERSION)
        require(
            authorization.status ==
                SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationStatus
                    .AUTHORIZED_FOR_SINGLE_REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF,
        )
        require(authorization.authorizationOnly)
        validateNonNetworkFlags(
            productionNetworkTouched = authorization.productionNetworkTouched,
            credentialLeaseMaterialRead = authorization.credentialLeaseMaterialRead,
            hostKeyPinVerifiedAgainstRemote = authorization.hostKeyPinVerifiedAgainstRemote,
            authorizesNetworkAccess = authorization.authorizesNetworkAccess,
            authorizesCredentialResolution = authorization.authorizesCredentialResolution,
            authorizesSshSessionAcquisition = authorization.authorizesSshSessionAcquisition,
            authorizesSftpChannelOpen = authorization.authorizesSftpChannelOpen,
            authorizesReadOnlyPreflightExecution = authorization.authorizesReadOnlyPreflightExecution,
            authorizesMutation = authorization.authorizesMutation,
            authorizesCoordinatorInvocation = authorization.authorizesCoordinatorInvocation,
            exposesDeployUiAction = authorization.exposesDeployUiAction,
            realVpsAccessAllowed = authorization.realVpsAccessAllowed,
        )
        require(authorization.authorizesSingleRealVpsReadOnlyPreflightHandoff)
        validateRequiredSeparation(
            durableConsumption = authorization.requiresDurableOneShotConsumptionBeforeAnyNetworkAccess,
            liveHostKeyVerification = authorization.requiresLiveRemoteHostKeyVerification,
            credentialResolution = authorization.requiresSeparateCredentialResolutionBoundary,
            sshSession = authorization.requiresSeparateSshSessionAcquisitionBoundary,
            sftpChannel = authorization.requiresSeparateSftpChannelOpenBoundary,
            readOnlyExecution = authorization.requiresSeparateReadOnlyExecutionBoundary,
            mutation = authorization.requiresSeparateMutationBoundary,
        )
        validateBoundProfile(
            vocabulary = authorization.approvedReadOnlyOperationVocabulary,
            maxTargetEntries = authorization.maxTargetEntries,
            probeImplementation = authorization.sftpReadOnlyProbeImplementation,
        )
        require(authorization.remotePort in 1..65535)
        require(authorization.authorizationExpiresAtEpochMillis > authorization.evaluatedAtEpochMillis)
        validateHashes(
            authorization.admissionSha256,
            authorization.serverAccessBindingSha256,
            authorization.requestSha256,
            authorization.capabilityProfileSha256,
            authorization.pinnedHostKeySha256,
            authorization.approvalChallengeSha256,
            authorization.authorizationSha256,
        )
        require(
            authorization.authorizationSha256 ==
                authorizationSha256(authorization.copy(authorizationSha256 = "")),
        )
    }

    private fun validateNonNetworkFlags(
        productionNetworkTouched: Boolean,
        credentialLeaseMaterialRead: Boolean,
        hostKeyPinVerifiedAgainstRemote: Boolean,
        authorizesNetworkAccess: Boolean,
        authorizesCredentialResolution: Boolean,
        authorizesSshSessionAcquisition: Boolean,
        authorizesSftpChannelOpen: Boolean,
        authorizesReadOnlyPreflightExecution: Boolean,
        authorizesMutation: Boolean,
        authorizesCoordinatorInvocation: Boolean,
        exposesDeployUiAction: Boolean,
        realVpsAccessAllowed: Boolean,
    ) {
        require(!productionNetworkTouched)
        require(!credentialLeaseMaterialRead)
        require(!hostKeyPinVerifiedAgainstRemote)
        require(!authorizesNetworkAccess)
        require(!authorizesCredentialResolution)
        require(!authorizesSshSessionAcquisition)
        require(!authorizesSftpChannelOpen)
        require(!authorizesReadOnlyPreflightExecution)
        require(!authorizesMutation)
        require(!authorizesCoordinatorInvocation)
        require(!exposesDeployUiAction)
        require(!realVpsAccessAllowed)
    }

    private fun validateRequiredSeparation(
        durableConsumption: Boolean,
        liveHostKeyVerification: Boolean,
        credentialResolution: Boolean,
        sshSession: Boolean,
        sftpChannel: Boolean,
        readOnlyExecution: Boolean,
        mutation: Boolean,
    ) {
        require(durableConsumption)
        require(liveHostKeyVerification)
        require(credentialResolution)
        require(sshSession)
        require(sftpChannel)
        require(readOnlyExecution)
        require(mutation)
    }

    private fun validateBoundProfile(
        vocabulary: List<String>,
        maxTargetEntries: Int,
        probeImplementation: String,
    ) {
        require(
            vocabulary ==
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
        )
        require(maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(probeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
    }

    private fun approvalChallengeSha256(
        draft: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft,
    ): String = sha256(
        buildString {
            append("phase=11.37\n")
            append("status=").append(draft.status.name).append('\n')
            append("admissionSha256=").append(draft.admissionSha256).append('\n')
            append("serverAccessBindingSha256=").append(draft.serverAccessBindingSha256).append('\n')
            append("requestSha256=").append(draft.requestSha256).append('\n')
            append("capabilityProfileSha256=").append(draft.capabilityProfileSha256).append('\n')
            append("authorizationAttemptId=").append(draft.authorizationAttemptId).append('\n')
            append("evaluatedAt=").append(draft.evaluatedAtEpochMillis).append('\n')
            append("expiresAt=").append(draft.authorizationExpiresAtEpochMillis).append('\n')
            draft.blockers.forEach {
                append("blocker=").append(it.code).append('\u0000').append(it.detail).append('\n')
            }
        },
    )

    private fun draftSha256(
        draft: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft,
    ): String = sha256(
        buildString {
            append("challenge=").append(draft.approvalChallengeSha256).append('\n')
            append("admission=").append(draft.admissionSha256).append('\n')
            append("binding=").append(draft.serverAccessBindingSha256).append('\n')
            append("request=").append(draft.requestSha256).append('\n')
            append("profile=").append(draft.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(draft.serverAccessId).append('\n')
            append("host=").append(draft.remoteHostIdentity).append('\n')
            append("port=").append(draft.remotePort).append('\n')
            append("hostKey=").append(draft.pinnedHostKeySha256).append('\n')
            append("target=").append(draft.targetRoot).append('\n')
            append("staging=").append(draft.stagingRoot).append('\n')
            append("backup=").append(draft.backupRoot).append('\n')
            draft.expectedTargetEntryNames.forEach { append("entry=").append(it).append('\n') }
            draft.approvedReadOnlyOperationVocabulary.forEach { append("operation=").append(it).append('\n') }
            append("maxTargetEntries=").append(draft.maxTargetEntries).append('\n')
            append("probe=").append(draft.sftpReadOnlyProbeImplementation).append('\n')
            append("attempt=").append(draft.authorizationAttemptId).append('\n')
            append("evaluatedAt=").append(draft.evaluatedAtEpochMillis).append('\n')
            append("expiresAt=").append(draft.authorizationExpiresAtEpochMillis).append('\n')
            append("status=").append(draft.status.name).append('\n')
        },
    )

    private fun authorizationSha256(
        authorization: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorization,
    ): String = sha256(
        buildString {
            append("phase=11.37\n")
            append("status=").append(authorization.status.name).append('\n')
            append("challenge=").append(authorization.approvalChallengeSha256).append('\n')
            append("admission=").append(authorization.admissionSha256).append('\n')
            append("binding=").append(authorization.serverAccessBindingSha256).append('\n')
            append("request=").append(authorization.requestSha256).append('\n')
            append("profile=").append(authorization.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(authorization.serverAccessId).append('\n')
            append("host=").append(authorization.remoteHostIdentity).append('\n')
            append("port=").append(authorization.remotePort).append('\n')
            append("hostKey=").append(authorization.pinnedHostKeySha256).append('\n')
            append("target=").append(authorization.targetRoot).append('\n')
            append("staging=").append(authorization.stagingRoot).append('\n')
            append("backup=").append(authorization.backupRoot).append('\n')
            authorization.expectedTargetEntryNames.forEach { append("entry=").append(it).append('\n') }
            authorization.approvedReadOnlyOperationVocabulary.forEach {
                append("operation=").append(it).append('\n')
            }
            append("maxTargetEntries=").append(authorization.maxTargetEntries).append('\n')
            append("probe=").append(authorization.sftpReadOnlyProbeImplementation).append('\n')
            append("attempt=").append(authorization.authorizationAttemptId).append('\n')
            append("evaluatedAt=").append(authorization.evaluatedAtEpochMillis).append('\n')
            append("expiresAt=").append(authorization.authorizationExpiresAtEpochMillis).append('\n')
            append("singleHandoff=")
                .append(authorization.authorizesSingleRealVpsReadOnlyPreflightHandoff)
                .append('\n')
        },
    )

    private fun safeAdd(left: Long, right: Long): Long =
        if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS read-only preflight authorization hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

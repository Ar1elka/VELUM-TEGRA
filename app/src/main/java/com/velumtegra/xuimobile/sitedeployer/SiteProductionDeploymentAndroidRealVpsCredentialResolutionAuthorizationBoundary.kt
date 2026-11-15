package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import java.security.MessageDigest

/**
 * Phase 11.39 non-network credential-resolution authorization over one exact consumed Phase 11.38
 * real-VPS read-only preflight handoff receipt.
 *
 * It recomputes the exact Phase 11.36 ServerAccess binding, hashes the authentication reference,
 * and binds the reviewed AndroidKeystoreSecretStore implementation identity. It does not instantiate
 * the store, read credential material, contact a network, verify a remote host key, acquire SSH/SFTP,
 * execute a remote read, mutate remote state, invoke the coordinator, or expose deploy UI.
 */
internal object SiteProductionDeploymentAndroidRealVpsCredentialResolutionAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 15_000L

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        receipt: SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft {
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightHandoffConsumptionBoundary
            .validateReceipt(receipt)
        require(receipt.singleUseConsumed) {
            "Real-VPS credential authorization requires a consumed Phase 11.38 handoff"
        }
        require(receipt.requiresSeparateCredentialResolutionBoundary) {
            "Consumed real-VPS handoff does not require credential resolution"
        }
        require(serverAccess.id.value == receipt.serverAccessId) {
            "Real-VPS credential authorization ServerAccess id mismatch"
        }
        require(canonicalId.matches(authorizationAttemptId)) {
            "Real-VPS credential authorization attempt id is not canonical"
        }
        require(evaluatedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "Real-VPS credential authorization cannot predate Phase 11.38 consumption"
        }
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "Real-VPS credential authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        val pinnedHostKeySha256 = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }
        val recomputedBindingSha256 = serverAccessBindingSha256(
            serverAccess = serverAccess,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            pinnedHostKeySha256 = pinnedHostKeySha256,
        )
        require(recomputedBindingSha256 == receipt.serverAccessBindingSha256) {
            "Real-VPS credential authorization ServerAccess binding does not match the consumed handoff"
        }

        val credentialStoreImplementation = AndroidKeystoreSecretStore::class.java.name
        val requestedExpiry = safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis)
        val authorizationExpiresAt = minOf(
            requestedExpiry,
            receipt.authorizationExpiresAtEpochMillis,
        )
        val blockers = buildList {
            if (evaluatedAtEpochMillis > receipt.authorizationExpiresAtEpochMillis) {
                add(
                    SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationBlocker(
                        code = "SOURCE_AUTHORIZATION_WINDOW_EXPIRED",
                        detail = "Phase 11.37 authorization window expired before credential authorization",
                    ),
                )
            }
            if (authorizationExpiresAt <= evaluatedAtEpochMillis) {
                add(
                    SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationBlocker(
                        code = "NO_SAFE_CREDENTIAL_RESOLUTION_AUTHORIZATION_WINDOW",
                        detail = "No positive credential-resolution authorization window remains",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus
                .AWAITING_EXPLICIT_CREDENTIAL_RESOLUTION_APPROVAL
        } else {
            SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus.BLOCKED
        }

        val challenge = approvalChallengeSha256(
            handoffConsumptionReceiptSha256 = receipt.consumptionReceiptSha256,
            sourceAuthorizationSha256 = receipt.authorizationSha256,
            admissionSha256 = receipt.admissionSha256,
            serverAccessBindingSha256 = receipt.serverAccessBindingSha256,
            requestSha256 = receipt.requestSha256,
            capabilityProfileSha256 = receipt.capabilityProfileSha256,
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            credentialStoreImplementation = credentialStoreImplementation,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorizationExpiresAt,
        )

        val base = SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            authorizationOnly = true,
            secretStoreReadPerformed = false,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSingleCredentialResolutionHandoff = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeCredentialResolution = true,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            handoffConsumptionReceiptSha256 = receipt.consumptionReceiptSha256,
            sourceAuthorizationSha256 = receipt.authorizationSha256,
            admissionSha256 = receipt.admissionSha256,
            serverAccessBindingSha256 = receipt.serverAccessBindingSha256,
            requestSha256 = receipt.requestSha256,
            capabilityProfileSha256 = receipt.capabilityProfileSha256,
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            credentialStoreImplementation = credentialStoreImplementation,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorizationExpiresAt,
            blockers = blockers,
            approvalChallengeSha256 = challenge,
            draftSha256 = "",
        )
        return base.copy(draftSha256 = draftSha256(base)).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsCredentialResolutionApproval,
    ): SiteProductionDeploymentRealVpsCredentialResolutionAuthorization {
        validateDraft(draft)
        require(
            draft.status ==
                SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus
                    .AWAITING_EXPLICIT_CREDENTIAL_RESOLUTION_APPROVAL,
        ) { "Blocked real-VPS credential-resolution authorization cannot be approved" }
        require(approval.confirmed) {
            "Real-VPS credential-resolution handoff requires explicit confirmation"
        }
        require(sha256Pattern.matches(approval.approvalChallengeSha256)) {
            "Real-VPS credential-resolution approval challenge SHA-256 is invalid"
        }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "Real-VPS credential-resolution approval is stale or bound to a different draft"
        }

        val base = SiteProductionDeploymentRealVpsCredentialResolutionAuthorization(
            contractVersion = draft.contractVersion,
            status = SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_CREDENTIAL_RESOLUTION_HANDOFF,
            authorizationOnly = true,
            secretStoreReadPerformed = false,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSingleCredentialResolutionHandoff = true,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeCredentialResolution = true,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            handoffConsumptionReceiptSha256 = draft.handoffConsumptionReceiptSha256,
            sourceAuthorizationSha256 = draft.sourceAuthorizationSha256,
            admissionSha256 = draft.admissionSha256,
            serverAccessBindingSha256 = draft.serverAccessBindingSha256,
            requestSha256 = draft.requestSha256,
            capabilityProfileSha256 = draft.capabilityProfileSha256,
            serverAccessId = draft.serverAccessId,
            secretReferenceType = draft.secretReferenceType,
            secretReferenceSha256 = draft.secretReferenceSha256,
            credentialStoreImplementation = draft.credentialStoreImplementation,
            authorizationAttemptId = draft.authorizationAttemptId,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            approvalChallengeSha256 = draft.approvalChallengeSha256,
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base))
            .also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION)
        require(draft.authorizationOnly)
        require(!draft.secretStoreReadPerformed)
        require(!draft.credentialLeaseMaterialRead)
        validateNonExecutionFlags(
            productionNetworkTouched = draft.productionNetworkTouched,
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
        require(!draft.authorizesSingleCredentialResolutionHandoff)
        require(draft.requiresExplicitApproval)
        validateRequiredSeparation(
            draft.requiresDurableOneShotConsumptionBeforeCredentialResolution,
            draft.requiresLiveRemoteHostKeyVerification,
            draft.requiresSeparateSshSessionAcquisitionBoundary,
            draft.requiresSeparateSftpChannelOpenBoundary,
            draft.requiresSeparateReadOnlyExecutionBoundary,
            draft.requiresSeparateMutationBoundary,
        )
        require(canonicalId.matches(draft.authorizationAttemptId))
        require(draft.secretReferenceType == "password" || draft.secretReferenceType == "private-key")
        require(draft.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        val expectedStatus = if (draft.blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus
                .AWAITING_EXPLICIT_CREDENTIAL_RESOLUTION_APPROVAL
        } else {
            SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus.BLOCKED
        }
        require(draft.status == expectedStatus)
        if (draft.blockers.isEmpty()) {
            require(draft.authorizationExpiresAtEpochMillis > draft.evaluatedAtEpochMillis)
        }
        validateHashes(
            draft.handoffConsumptionReceiptSha256,
            draft.sourceAuthorizationSha256,
            draft.admissionSha256,
            draft.serverAccessBindingSha256,
            draft.requestSha256,
            draft.capabilityProfileSha256,
            draft.secretReferenceSha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = "")))
    }

    fun validateAuthorization(
        authorization: SiteProductionDeploymentRealVpsCredentialResolutionAuthorization,
    ) {
        require(authorization.contractVersion == CONTRACT_VERSION)
        require(
            authorization.status ==
                SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationStatus
                    .AUTHORIZED_FOR_SINGLE_CREDENTIAL_RESOLUTION_HANDOFF,
        )
        require(authorization.authorizationOnly)
        require(!authorization.secretStoreReadPerformed)
        require(!authorization.credentialLeaseMaterialRead)
        validateNonExecutionFlags(
            productionNetworkTouched = authorization.productionNetworkTouched,
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
        require(authorization.authorizesSingleCredentialResolutionHandoff)
        validateRequiredSeparation(
            authorization.requiresDurableOneShotConsumptionBeforeCredentialResolution,
            authorization.requiresLiveRemoteHostKeyVerification,
            authorization.requiresSeparateSshSessionAcquisitionBoundary,
            authorization.requiresSeparateSftpChannelOpenBoundary,
            authorization.requiresSeparateReadOnlyExecutionBoundary,
            authorization.requiresSeparateMutationBoundary,
        )
        require(authorization.authorizationExpiresAtEpochMillis > authorization.evaluatedAtEpochMillis)
        require(authorization.secretReferenceType == "password" || authorization.secretReferenceType == "private-key")
        require(authorization.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        validateHashes(
            authorization.handoffConsumptionReceiptSha256,
            authorization.sourceAuthorizationSha256,
            authorization.admissionSha256,
            authorization.serverAccessBindingSha256,
            authorization.requestSha256,
            authorization.capabilityProfileSha256,
            authorization.secretReferenceSha256,
            authorization.approvalChallengeSha256,
            authorization.authorizationSha256,
        )
        require(
            authorization.authorizationSha256 ==
                authorizationSha256(authorization.copy(authorizationSha256 = "")),
        )
    }

    private fun validateNonExecutionFlags(
        productionNetworkTouched: Boolean,
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
        sshSession: Boolean,
        sftpChannel: Boolean,
        readOnlyExecution: Boolean,
        mutation: Boolean,
    ) {
        require(durableConsumption)
        require(liveHostKeyVerification)
        require(sshSession)
        require(sftpChannel)
        require(readOnlyExecution)
        require(mutation)
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
        handoffConsumptionReceiptSha256: String,
        sourceAuthorizationSha256: String,
        admissionSha256: String,
        serverAccessBindingSha256: String,
        requestSha256: String,
        capabilityProfileSha256: String,
        serverAccessId: String,
        secretReferenceType: String,
        secretReferenceSha256: String,
        credentialStoreImplementation: String,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        authorizationExpiresAtEpochMillis: Long,
    ): String = sha256(
        buildString {
            append("phase=11.39\n")
            append("handoffReceipt=").append(handoffConsumptionReceiptSha256).append('\n')
            append("sourceAuthorization=").append(sourceAuthorizationSha256).append('\n')
            append("admission=").append(admissionSha256).append('\n')
            append("binding=").append(serverAccessBindingSha256).append('\n')
            append("request=").append(requestSha256).append('\n')
            append("profile=").append(capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(serverAccessId).append('\n')
            append("secretReferenceType=").append(secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(credentialStoreImplementation).append('\n')
            append("attempt=").append(authorizationAttemptId).append('\n')
            append("evaluatedAt=").append(evaluatedAtEpochMillis).append('\n')
            append("expiresAt=").append(authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun draftSha256(
        draft: SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft,
    ): String = sha256(
        buildString {
            appendCommon(
                handoffConsumptionReceiptSha256 = draft.handoffConsumptionReceiptSha256,
                sourceAuthorizationSha256 = draft.sourceAuthorizationSha256,
                admissionSha256 = draft.admissionSha256,
                serverAccessBindingSha256 = draft.serverAccessBindingSha256,
                requestSha256 = draft.requestSha256,
                capabilityProfileSha256 = draft.capabilityProfileSha256,
                serverAccessId = draft.serverAccessId,
                secretReferenceType = draft.secretReferenceType,
                secretReferenceSha256 = draft.secretReferenceSha256,
                credentialStoreImplementation = draft.credentialStoreImplementation,
                authorizationAttemptId = draft.authorizationAttemptId,
                evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
                authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            )
            append("status=").append(draft.status.name).append('\n')
            append("requiresExplicitApproval=").append(draft.requiresExplicitApproval).append('\n')
            draft.blockers.forEach {
                append("blocker=").append(it.code).append('\u0000').append(it.detail).append('\n')
            }
            append("approvalChallenge=").append(draft.approvalChallengeSha256).append('\n')
        },
    )

    private fun authorizationSha256(
        authorization: SiteProductionDeploymentRealVpsCredentialResolutionAuthorization,
    ): String = sha256(
        buildString {
            appendCommon(
                handoffConsumptionReceiptSha256 = authorization.handoffConsumptionReceiptSha256,
                sourceAuthorizationSha256 = authorization.sourceAuthorizationSha256,
                admissionSha256 = authorization.admissionSha256,
                serverAccessBindingSha256 = authorization.serverAccessBindingSha256,
                requestSha256 = authorization.requestSha256,
                capabilityProfileSha256 = authorization.capabilityProfileSha256,
                serverAccessId = authorization.serverAccessId,
                secretReferenceType = authorization.secretReferenceType,
                secretReferenceSha256 = authorization.secretReferenceSha256,
                credentialStoreImplementation = authorization.credentialStoreImplementation,
                authorizationAttemptId = authorization.authorizationAttemptId,
                evaluatedAtEpochMillis = authorization.evaluatedAtEpochMillis,
                authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            )
            append("status=").append(authorization.status.name).append('\n')
            append("singleCredentialHandoff=")
                .append(authorization.authorizesSingleCredentialResolutionHandoff)
                .append('\n')
            append("approvalChallenge=").append(authorization.approvalChallengeSha256).append('\n')
        },
    )

    private fun StringBuilder.appendCommon(
        handoffConsumptionReceiptSha256: String,
        sourceAuthorizationSha256: String,
        admissionSha256: String,
        serverAccessBindingSha256: String,
        requestSha256: String,
        capabilityProfileSha256: String,
        serverAccessId: String,
        secretReferenceType: String,
        secretReferenceSha256: String,
        credentialStoreImplementation: String,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        authorizationExpiresAtEpochMillis: Long,
    ) {
        append("contractVersion=").append(CONTRACT_VERSION).append('\n')
        append("authorizationOnly=true\n")
        append("secretStoreReadPerformed=false\n")
        append("credentialLeaseMaterialRead=false\n")
        append("productionNetworkTouched=false\n")
        append("hostKeyPinVerifiedAgainstRemote=false\n")
        append("authorizesNetworkAccess=false\n")
        append("authorizesCredentialResolution=false\n")
        append("authorizesSshSessionAcquisition=false\n")
        append("authorizesSftpChannelOpen=false\n")
        append("authorizesReadOnlyPreflightExecution=false\n")
        append("authorizesMutation=false\n")
        append("authorizesCoordinatorInvocation=false\n")
        append("exposesDeployUiAction=false\n")
        append("realVpsAccessAllowed=false\n")
        append("requiresDurableOneShotConsumptionBeforeCredentialResolution=true\n")
        append("requiresLiveRemoteHostKeyVerification=true\n")
        append("requiresSeparateSshSessionAcquisitionBoundary=true\n")
        append("requiresSeparateSftpChannelOpenBoundary=true\n")
        append("requiresSeparateReadOnlyExecutionBoundary=true\n")
        append("requiresSeparateMutationBoundary=true\n")
        append("handoffReceipt=").append(handoffConsumptionReceiptSha256).append('\n')
        append("sourceAuthorization=").append(sourceAuthorizationSha256).append('\n')
        append("admission=").append(admissionSha256).append('\n')
        append("binding=").append(serverAccessBindingSha256).append('\n')
        append("request=").append(requestSha256).append('\n')
        append("profile=").append(capabilityProfileSha256).append('\n')
        append("serverAccessId=").append(serverAccessId).append('\n')
        append("secretReferenceType=").append(secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
        append("credentialStoreImplementation=").append(credentialStoreImplementation).append('\n')
        append("attempt=").append(authorizationAttemptId).append('\n')
        append("evaluatedAt=").append(evaluatedAtEpochMillis).append('\n')
        append("expiresAt=").append(authorizationExpiresAtEpochMillis).append('\n')
    }

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS credential-resolution authorization hashes must be lowercase SHA-256"
        }
    }

    private fun safeAdd(left: Long, right: Long): Long {
        require(right >= 0L)
        require(left <= Long.MAX_VALUE - right) {
            "Real-VPS credential-resolution authorization expiry overflows Long"
        }
        return left + right
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

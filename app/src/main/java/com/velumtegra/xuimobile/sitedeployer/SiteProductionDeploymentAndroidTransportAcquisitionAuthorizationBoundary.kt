package com.velumtegra.xuimobile.sitedeployer

import java.security.MessageDigest

/**
 * Non-executing approval boundary for a future production transport-acquisition adapter.
 *
 * This boundary may issue only a short-lived, single-use handoff authorization. It never resolves
 * credentials, acquires SSH, opens SFTP, invokes the deployment coordinator, exposes deploy UI, or
 * enables production transport. A future phase must add durable one-shot consumption and a separate
 * execution adapter before any transport acquisition can occur.
 */
internal object SiteProductionDeploymentAndroidTransportAcquisitionAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 30_000L

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        request: SiteProductionDeploymentTransportAcquisitionAuthorizationRequest,
    ): SiteProductionDeploymentTransportAcquisitionAuthorizationDraft {
        require(canonicalId.matches(request.authorizationAttemptId)) {
            "Transport-acquisition authorization attempt id must be a canonical 8..128 character identifier"
        }
        require(request.evaluatedAtEpochMillis >= 0L) {
            "Transport-acquisition authorization evaluation time must be non-negative"
        }
        require(request.requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "Transport-acquisition authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }

        val rebuiltReadiness = SiteProductionDeploymentAndroidTransportAcquisitionReadinessGate.prepare(
            request.readinessRequest,
        )
        require(rebuiltReadiness == request.readinessDescriptor) {
            "Transport-acquisition readiness descriptor is stale, tampered, or bound to different evidence"
        }
        SiteProductionDeploymentAndroidTransportAcquisitionReadinessGate.validate(request.readinessDescriptor)
        require(
            request.readinessDescriptor.status ==
                SiteProductionDeploymentTransportAcquisitionReadinessStatus.READY_FOR_SEPARATE_TRANSPORT_ACQUISITION,
        ) { "Blocked transport-acquisition readiness cannot enter authorization" }
        require(request.readinessDescriptor.requiresSeparateTransportAcquisitionAuthorization) {
            "Readiness descriptor does not require this authorization boundary"
        }
        require(request.evaluatedAtEpochMillis >= request.readinessDescriptor.evaluatedAtEpochMillis) {
            "Transport-acquisition authorization cannot predate readiness evaluation"
        }

        val requestedExpiry = safeAdd(
            request.evaluatedAtEpochMillis,
            request.requestedAuthorizationLifetimeMillis,
        )
        val evidenceExpiresAt = minOf(
            request.readinessDescriptor.executionEvidenceExpiresAtEpochMillis,
            request.readinessDescriptor.runtimeMutationPermitExpiresAtEpochMillis,
        )
        val authorizationExpiresAt = minOf(requestedExpiry, evidenceExpiresAt)
        val blockers = buildList {
            if (request.evaluatedAtEpochMillis > evidenceExpiresAt) {
                add(
                    SiteProductionDeploymentTransportAcquisitionAuthorizationBlocker(
                        code = "TRANSPORT_ACQUISITION_EVIDENCE_STALE",
                        detail = "Readiness/execution/runtime-mutation evidence expired before acquisition authorization",
                    ),
                )
            }
            if (authorizationExpiresAt <= request.evaluatedAtEpochMillis) {
                add(
                    SiteProductionDeploymentTransportAcquisitionAuthorizationBlocker(
                        code = "NO_SAFE_TRANSPORT_ACQUISITION_WINDOW",
                        detail = "No positive authorization window remains before current evidence expires",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.AWAITING_TRANSPORT_ACQUISITION_APPROVAL
        } else {
            SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.BLOCKED
        }
        val challenge = approvalChallengeSha256(
            request = request,
            authorizationExpiresAtEpochMillis = authorizationExpiresAt,
        )
        val base = SiteProductionDeploymentTransportAcquisitionAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            authorizationOnly = true,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            authorizesSingleTransportAcquisitionHandoff = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeAcquisition = true,
            authorizationAttemptId = request.authorizationAttemptId,
            readinessSha256 = request.readinessDescriptor.readinessSha256,
            compositionDescriptorSha256 = request.readinessDescriptor.compositionDescriptorSha256,
            serverIdentitySha256 = request.readinessDescriptor.serverIdentitySha256,
            runtimeSessionId = request.readinessDescriptor.runtimeSessionId,
            remoteHostIdentity = request.readinessDescriptor.remoteHostIdentity,
            executionAttemptId = request.readinessDescriptor.executionAttemptId,
            coordinatorInvocationId = request.readinessDescriptor.coordinatorInvocationId,
            runtimeMutationPermitSha256 = request.readinessDescriptor.runtimeMutationPermitSha256,
            candidateTransportAuthorizationSha256 =
                request.readinessDescriptor.candidateTransportAuthorizationSha256,
            boundedSftpImplementationId = request.readinessDescriptor.boundedSftpImplementationId,
            boundedSftpCapabilityProfileSha256 =
                request.readinessDescriptor.boundedSftpCapabilityProfileSha256,
            evaluatedAtEpochMillis = request.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorizationExpiresAt,
            blockers = blockers,
            approvalChallengeSha256 = challenge,
            draftSha256 = "",
        )
        return base.copy(draftSha256 = draftSha256(base)).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentTransportAcquisitionAuthorizationDraft,
        approval: SiteProductionDeploymentTransportAcquisitionApproval,
    ): SiteProductionDeploymentTransportAcquisitionAuthorization {
        validateDraft(draft)
        require(
            draft.status ==
                SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.AWAITING_TRANSPORT_ACQUISITION_APPROVAL,
        ) { "Blocked transport-acquisition authorization draft cannot be approved" }
        require(approval.confirmed) { "Transport-acquisition handoff requires explicit confirmation" }
        require(sha256.matches(approval.approvalChallengeSha256)) {
            "Transport-acquisition approval challenge SHA-256 is invalid"
        }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "Transport-acquisition approval is stale or bound to a different draft"
        }

        val base = SiteProductionDeploymentTransportAcquisitionAuthorization(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.AUTHORIZED_FOR_SINGLE_TRANSPORT_ACQUISITION_HANDOFF,
            authorizationOnly = true,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            authorizesSingleTransportAcquisitionHandoff = true,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeAcquisition = true,
            authorizationAttemptId = draft.authorizationAttemptId,
            readinessSha256 = draft.readinessSha256,
            compositionDescriptorSha256 = draft.compositionDescriptorSha256,
            serverIdentitySha256 = draft.serverIdentitySha256,
            runtimeSessionId = draft.runtimeSessionId,
            remoteHostIdentity = draft.remoteHostIdentity,
            executionAttemptId = draft.executionAttemptId,
            coordinatorInvocationId = draft.coordinatorInvocationId,
            runtimeMutationPermitSha256 = draft.runtimeMutationPermitSha256,
            candidateTransportAuthorizationSha256 = draft.candidateTransportAuthorizationSha256,
            boundedSftpImplementationId = draft.boundedSftpImplementationId,
            boundedSftpCapabilityProfileSha256 = draft.boundedSftpCapabilityProfileSha256,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            approvalChallengeSha256 = draft.approvalChallengeSha256,
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base)).also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentTransportAcquisitionAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION) { "Unsupported transport-acquisition authorization contract" }
        require(draft.authorizationOnly) { "Transport-acquisition draft must remain authorization-only" }
        require(!draft.productionTransportEnabled) { "Production transport must remain disabled" }
        require(!draft.authorizesTransport) { "Authorization draft must not authorize transport mutation" }
        require(!draft.authorizesCredentialResolution) { "Authorization draft must not authorize credential resolution" }
        require(!draft.authorizesSshSessionAcquisition) { "Authorization draft must not authorize SSH acquisition" }
        require(!draft.authorizesSftpChannelOpen) { "Authorization draft must not authorize SFTP open" }
        require(!draft.authorizesCoordinatorInvocation) { "Authorization draft must not authorize coordinator invocation" }
        require(!draft.authorizesSingleTransportAcquisitionHandoff) {
            "Unapproved authorization draft must not authorize acquisition handoff"
        }
        require(!draft.exposesDeployUiAction) { "Authorization draft must not expose deploy UI" }
        require(!draft.realVpsAccessAllowed) { "Authorization draft must not allow real VPS access" }
        require(draft.requiresExplicitApproval) { "Transport-acquisition authorization must require explicit approval" }
        require(draft.requiresDurableOneShotConsumptionBeforeAcquisition) {
            "Durable one-shot consumption before acquisition must remain mandatory"
        }
        require(canonicalId.matches(draft.authorizationAttemptId)) {
            "Transport-acquisition authorization attempt id is invalid"
        }
        require(draft.evaluatedAtEpochMillis >= 0L) { "Authorization evaluation time is invalid" }
        require(draft.authorizationExpiresAtEpochMillis >= 0L) { "Authorization expiry is invalid" }
        val expectedStatus = if (draft.blockers.isEmpty()) {
            SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.AWAITING_TRANSPORT_ACQUISITION_APPROVAL
        } else {
            SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.BLOCKED
        }
        require(draft.status == expectedStatus) { "Authorization draft status does not match blockers" }
        validateHashes(
            draft.readinessSha256,
            draft.compositionDescriptorSha256,
            draft.serverIdentitySha256,
            draft.runtimeMutationPermitSha256,
            draft.candidateTransportAuthorizationSha256,
            draft.boundedSftpCapabilityProfileSha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = ""))) {
            "Transport-acquisition authorization draft SHA-256 mismatch"
        }
    }

    fun validateAuthorization(
        authorization: SiteProductionDeploymentTransportAcquisitionAuthorization,
    ) {
        require(authorization.contractVersion == CONTRACT_VERSION) {
            "Unsupported transport-acquisition authorization contract"
        }
        require(
            authorization.status ==
                SiteProductionDeploymentTransportAcquisitionAuthorizationStatus.AUTHORIZED_FOR_SINGLE_TRANSPORT_ACQUISITION_HANDOFF,
        ) { "Transport-acquisition authorization has invalid status" }
        require(authorization.authorizationOnly) { "Transport-acquisition authorization must remain authorization-only" }
        require(!authorization.productionTransportEnabled) { "Production transport must remain disabled" }
        require(!authorization.authorizesTransport) { "Authorization must not authorize transport mutation" }
        require(!authorization.authorizesCredentialResolution) { "Authorization must not resolve credentials" }
        require(!authorization.authorizesSshSessionAcquisition) { "Authorization must not acquire SSH" }
        require(!authorization.authorizesSftpChannelOpen) { "Authorization must not open SFTP" }
        require(!authorization.authorizesCoordinatorInvocation) { "Authorization must not invoke coordinator" }
        require(authorization.authorizesSingleTransportAcquisitionHandoff) {
            "Authorization must authorize exactly one future acquisition handoff"
        }
        require(!authorization.exposesDeployUiAction) { "Authorization must not expose deploy UI" }
        require(!authorization.realVpsAccessAllowed) { "Authorization must not allow real VPS access" }
        require(authorization.requiresDurableOneShotConsumptionBeforeAcquisition) {
            "Future acquisition must require durable one-shot consumption"
        }
        require(canonicalId.matches(authorization.authorizationAttemptId)) {
            "Transport-acquisition authorization attempt id is invalid"
        }
        require(authorization.authorizationExpiresAtEpochMillis > authorization.evaluatedAtEpochMillis) {
            "Transport-acquisition authorization has no positive validity window"
        }
        validateHashes(
            authorization.readinessSha256,
            authorization.compositionDescriptorSha256,
            authorization.serverIdentitySha256,
            authorization.runtimeMutationPermitSha256,
            authorization.candidateTransportAuthorizationSha256,
            authorization.boundedSftpCapabilityProfileSha256,
            authorization.approvalChallengeSha256,
            authorization.authorizationSha256,
        )
        require(
            authorization.authorizationSha256 ==
                authorizationSha256(authorization.copy(authorizationSha256 = "")),
        ) { "Transport-acquisition authorization SHA-256 mismatch" }
    }

    private fun approvalChallengeSha256(
        request: SiteProductionDeploymentTransportAcquisitionAuthorizationRequest,
        authorizationExpiresAtEpochMillis: Long,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(CONTRACT_VERSION).append('\n')
            append("authorizationAttemptId=").append(request.authorizationAttemptId).append('\n')
            append("readinessSha256=").append(request.readinessDescriptor.readinessSha256).append('\n')
            append("compositionDescriptorSha256=").append(request.readinessDescriptor.compositionDescriptorSha256).append('\n')
            append("serverIdentitySha256=").append(request.readinessDescriptor.serverIdentitySha256).append('\n')
            append("runtimeSessionId=").append(request.readinessDescriptor.runtimeSessionId).append('\n')
            append("remoteHostIdentity=").append(request.readinessDescriptor.remoteHostIdentity).append('\n')
            append("executionAttemptId=").append(request.readinessDescriptor.executionAttemptId).append('\n')
            append("coordinatorInvocationId=").append(request.readinessDescriptor.coordinatorInvocationId).append('\n')
            append("runtimeMutationPermitSha256=").append(request.readinessDescriptor.runtimeMutationPermitSha256).append('\n')
            append("candidateTransportAuthorizationSha256=")
                .append(request.readinessDescriptor.candidateTransportAuthorizationSha256).append('\n')
            append("boundedSftpImplementationId=").append(request.readinessDescriptor.boundedSftpImplementationId).append('\n')
            append("boundedSftpCapabilityProfileSha256=")
                .append(request.readinessDescriptor.boundedSftpCapabilityProfileSha256).append('\n')
            append("evaluatedAtEpochMillis=").append(request.evaluatedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=").append(authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun draftSha256(
        draft: SiteProductionDeploymentTransportAcquisitionAuthorizationDraft,
    ): String = sha256(
        buildString {
            appendCommon(
                authorizationOnly = draft.authorizationOnly,
                productionTransportEnabled = draft.productionTransportEnabled,
                authorizesTransport = draft.authorizesTransport,
                authorizesCredentialResolution = draft.authorizesCredentialResolution,
                authorizesSshSessionAcquisition = draft.authorizesSshSessionAcquisition,
                authorizesSftpChannelOpen = draft.authorizesSftpChannelOpen,
                authorizesCoordinatorInvocation = draft.authorizesCoordinatorInvocation,
                authorizesSingleTransportAcquisitionHandoff = draft.authorizesSingleTransportAcquisitionHandoff,
                exposesDeployUiAction = draft.exposesDeployUiAction,
                realVpsAccessAllowed = draft.realVpsAccessAllowed,
                authorizationAttemptId = draft.authorizationAttemptId,
                readinessSha256 = draft.readinessSha256,
                compositionDescriptorSha256 = draft.compositionDescriptorSha256,
                serverIdentitySha256 = draft.serverIdentitySha256,
                runtimeSessionId = draft.runtimeSessionId,
                remoteHostIdentity = draft.remoteHostIdentity,
                executionAttemptId = draft.executionAttemptId,
                coordinatorInvocationId = draft.coordinatorInvocationId,
                runtimeMutationPermitSha256 = draft.runtimeMutationPermitSha256,
                candidateTransportAuthorizationSha256 = draft.candidateTransportAuthorizationSha256,
                boundedSftpImplementationId = draft.boundedSftpImplementationId,
                boundedSftpCapabilityProfileSha256 = draft.boundedSftpCapabilityProfileSha256,
                evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
                authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            )
            append("status=").append(draft.status.name).append('\n')
            append("requiresExplicitApproval=").append(draft.requiresExplicitApproval).append('\n')
            append("requiresDurableOneShotConsumptionBeforeAcquisition=")
                .append(draft.requiresDurableOneShotConsumptionBeforeAcquisition).append('\n')
            draft.blockers.forEach { blocker ->
                append("blocker=").append(blocker.code).append('\u0000').append(blocker.detail).append('\n')
            }
            append("approvalChallengeSha256=").append(draft.approvalChallengeSha256).append('\n')
        },
    )

    private fun authorizationSha256(
        authorization: SiteProductionDeploymentTransportAcquisitionAuthorization,
    ): String = sha256(
        buildString {
            appendCommon(
                authorizationOnly = authorization.authorizationOnly,
                productionTransportEnabled = authorization.productionTransportEnabled,
                authorizesTransport = authorization.authorizesTransport,
                authorizesCredentialResolution = authorization.authorizesCredentialResolution,
                authorizesSshSessionAcquisition = authorization.authorizesSshSessionAcquisition,
                authorizesSftpChannelOpen = authorization.authorizesSftpChannelOpen,
                authorizesCoordinatorInvocation = authorization.authorizesCoordinatorInvocation,
                authorizesSingleTransportAcquisitionHandoff =
                    authorization.authorizesSingleTransportAcquisitionHandoff,
                exposesDeployUiAction = authorization.exposesDeployUiAction,
                realVpsAccessAllowed = authorization.realVpsAccessAllowed,
                authorizationAttemptId = authorization.authorizationAttemptId,
                readinessSha256 = authorization.readinessSha256,
                compositionDescriptorSha256 = authorization.compositionDescriptorSha256,
                serverIdentitySha256 = authorization.serverIdentitySha256,
                runtimeSessionId = authorization.runtimeSessionId,
                remoteHostIdentity = authorization.remoteHostIdentity,
                executionAttemptId = authorization.executionAttemptId,
                coordinatorInvocationId = authorization.coordinatorInvocationId,
                runtimeMutationPermitSha256 = authorization.runtimeMutationPermitSha256,
                candidateTransportAuthorizationSha256 = authorization.candidateTransportAuthorizationSha256,
                boundedSftpImplementationId = authorization.boundedSftpImplementationId,
                boundedSftpCapabilityProfileSha256 = authorization.boundedSftpCapabilityProfileSha256,
                evaluatedAtEpochMillis = authorization.evaluatedAtEpochMillis,
                authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            )
            append("status=").append(authorization.status.name).append('\n')
            append("requiresDurableOneShotConsumptionBeforeAcquisition=")
                .append(authorization.requiresDurableOneShotConsumptionBeforeAcquisition).append('\n')
            append("approvalChallengeSha256=").append(authorization.approvalChallengeSha256).append('\n')
        },
    )

    private fun StringBuilder.appendCommon(
        authorizationOnly: Boolean,
        productionTransportEnabled: Boolean,
        authorizesTransport: Boolean,
        authorizesCredentialResolution: Boolean,
        authorizesSshSessionAcquisition: Boolean,
        authorizesSftpChannelOpen: Boolean,
        authorizesCoordinatorInvocation: Boolean,
        authorizesSingleTransportAcquisitionHandoff: Boolean,
        exposesDeployUiAction: Boolean,
        realVpsAccessAllowed: Boolean,
        authorizationAttemptId: String,
        readinessSha256: String,
        compositionDescriptorSha256: String,
        serverIdentitySha256: String,
        runtimeSessionId: String,
        remoteHostIdentity: String,
        executionAttemptId: String,
        coordinatorInvocationId: String,
        runtimeMutationPermitSha256: String,
        candidateTransportAuthorizationSha256: String,
        boundedSftpImplementationId: String,
        boundedSftpCapabilityProfileSha256: String,
        evaluatedAtEpochMillis: Long,
        authorizationExpiresAtEpochMillis: Long,
    ) {
        append("contractVersion=").append(CONTRACT_VERSION).append('\n')
        append("authorizationOnly=").append(authorizationOnly).append('\n')
        append("productionTransportEnabled=").append(productionTransportEnabled).append('\n')
        append("authorizesTransport=").append(authorizesTransport).append('\n')
        append("authorizesCredentialResolution=").append(authorizesCredentialResolution).append('\n')
        append("authorizesSshSessionAcquisition=").append(authorizesSshSessionAcquisition).append('\n')
        append("authorizesSftpChannelOpen=").append(authorizesSftpChannelOpen).append('\n')
        append("authorizesCoordinatorInvocation=").append(authorizesCoordinatorInvocation).append('\n')
        append("authorizesSingleTransportAcquisitionHandoff=")
            .append(authorizesSingleTransportAcquisitionHandoff).append('\n')
        append("exposesDeployUiAction=").append(exposesDeployUiAction).append('\n')
        append("realVpsAccessAllowed=").append(realVpsAccessAllowed).append('\n')
        append("authorizationAttemptId=").append(authorizationAttemptId).append('\n')
        append("readinessSha256=").append(readinessSha256).append('\n')
        append("compositionDescriptorSha256=").append(compositionDescriptorSha256).append('\n')
        append("serverIdentitySha256=").append(serverIdentitySha256).append('\n')
        append("runtimeSessionId=").append(runtimeSessionId).append('\n')
        append("remoteHostIdentity=").append(remoteHostIdentity).append('\n')
        append("executionAttemptId=").append(executionAttemptId).append('\n')
        append("coordinatorInvocationId=").append(coordinatorInvocationId).append('\n')
        append("runtimeMutationPermitSha256=").append(runtimeMutationPermitSha256).append('\n')
        append("candidateTransportAuthorizationSha256=").append(candidateTransportAuthorizationSha256).append('\n')
        append("boundedSftpImplementationId=").append(boundedSftpImplementationId).append('\n')
        append("boundedSftpCapabilityProfileSha256=").append(boundedSftpCapabilityProfileSha256).append('\n')
        append("evaluatedAtEpochMillis=").append(evaluatedAtEpochMillis).append('\n')
        append("authorizationExpiresAtEpochMillis=").append(authorizationExpiresAtEpochMillis).append('\n')
    }

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256::matches)) { "Transport-acquisition authorization hashes must be lowercase SHA-256" }
    }

    private fun safeAdd(left: Long, right: Long): Long {
        require(right >= 0L) { "Transport-acquisition authorization lifetime must be non-negative" }
        require(left <= Long.MAX_VALUE - right) { "Transport-acquisition authorization expiry overflows Long" }
        return left + right
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

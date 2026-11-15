package com.velumtegra.xuimobile.core.site

object SiteProductionDeploymentExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val executionAttemptId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(request: SiteProductionDeploymentExecutionRequest): SiteProductionDeploymentExecutionDraft {
        require(executionAttemptId.matches(request.executionAttemptId)) {
            "Execution attempt id must be a canonical 8..128 character identifier"
        }
        require(request.evaluatedAtEpochMillis >= 0L) { "Execution evaluation time must be non-negative" }

        val rebuiltReadiness = SiteProductionDeploymentReadinessBoundary.prepare(request.readinessRequest)
        require(rebuiltReadiness.status == SiteProductionDeploymentReadinessStatus.AWAITING_OPERATOR_APPROVAL) {
            "Execution authorization requires currently READY readiness evidence"
        }
        val rebuiltReadyRecord = SiteProductionDeploymentReadinessBoundary.approve(
            rebuiltReadiness,
            SiteProductionOperatorApproval(
                operatorApprovalChallengeSha256 = rebuiltReadiness.operatorApprovalChallengeSha256,
                confirmed = true,
            ),
        )
        require(rebuiltReadyRecord == request.readyRecord) {
            "Ready record is stale, tampered, or bound to different readiness inputs"
        }
        require(request.evaluatedAtEpochMillis >= request.readyRecord.evaluatedAtEpochMillis) {
            "Execution evaluation cannot predate readiness approval"
        }
        require(request.coordinatorRequest.exportPlan == request.readinessRequest.exportPlan) {
            "Coordinator export plan differs from approved readiness export plan"
        }
        require(request.coordinatorRequest.remoteRequest == request.readinessRequest.remoteRequest) {
            "Coordinator remote request differs from approved readiness request"
        }
        require(request.coordinatorRequest.trust == request.readinessRequest.trust) {
            "Coordinator trust differs from approved readiness trust"
        }

        val candidateTransportAuthorization = SiteRemoteTransportBoundary.authorize(
            plan = rebuiltReadiness.deploymentPlan,
            preflight = rebuiltReadiness.preflight,
            capabilities = request.transportCapabilities,
        )
        require(candidateTransportAuthorization.deploymentPlanSha256 == request.readyRecord.deploymentPlanSha256) {
            "Candidate transport authorization is bound to a different deployment plan"
        }
        require(candidateTransportAuthorization.preflightSha256 == request.readyRecord.preflightSha256) {
            "Candidate transport authorization is bound to different preflight evidence"
        }
        require(candidateTransportAuthorization.sourceTreeSha256 == request.readyRecord.sourceTreeSha256) {
            "Candidate transport authorization is bound to a different source tree"
        }

        val coordinatorSha256 = coordinatorRequestSha256(request.coordinatorRequest)
        val capabilitySha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(request.transportCapabilities)
        require(candidateTransportAuthorization.capabilityProfileSha256 == capabilitySha256) {
            "Candidate transport capability profile mismatch"
        }
        val expiresAt = minOf(
            safeExpiry(
                request.readyRecord.remoteObservationObservedAtEpochMillis,
                request.readyRecord.maxObservationAgeMillis,
            ),
            safeExpiry(
                request.readyRecord.serviceBindingObservedAtEpochMillis,
                request.readyRecord.maxObservationAgeMillis,
            ),
        )
        val blockers = buildList {
            if (request.evaluatedAtEpochMillis > expiresAt) {
                add(
                    SiteProductionDeploymentExecutionBlocker(
                        code = "READINESS_EVIDENCE_STALE",
                        detail = "Approved remote/service observations expired before execution authorization",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentExecutionStatus.AWAITING_EXECUTION_APPROVAL
        } else {
            SiteProductionDeploymentExecutionStatus.BLOCKED
        }
        val challenge = executionApprovalChallengeSha256(
            request = request,
            coordinatorRequestSha256 = coordinatorSha256,
            capabilityProfileSha256 = capabilitySha256,
            candidateTransportAuthorizationSha256 = candidateTransportAuthorization.authorizationSha256,
            evidenceExpiresAtEpochMillis = expiresAt,
        )
        val base = SiteProductionDeploymentExecutionDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            realServerMutationEnabled = false,
            authorizesTransport = false,
            authorizesCoordinatorHandoff = false,
            requiresRuntimeMutationEnablement = true,
            executionAttemptId = request.executionAttemptId,
            readyRecordSha256 = request.readyRecord.approvalRecordSha256,
            readinessSha256 = request.readyRecord.readinessSha256,
            deploymentPlanSha256 = request.readyRecord.deploymentPlanSha256,
            preflightSha256 = request.readyRecord.preflightSha256,
            exportPlanSha256 = request.readyRecord.exportPlanSha256,
            sourceTreeSha256 = request.readyRecord.sourceTreeSha256,
            coordinatorRequestSha256 = coordinatorSha256,
            capabilityProfileSha256 = capabilitySha256,
            candidateTransportAuthorizationSha256 = candidateTransportAuthorization.authorizationSha256,
            evaluatedAtEpochMillis = request.evaluatedAtEpochMillis,
            evidenceExpiresAtEpochMillis = expiresAt,
            blockers = blockers,
            executionApprovalChallengeSha256 = challenge,
            executionDraftSha256 = "",
        )
        return base.copy(
            executionDraftSha256 = executionDraftSha256(base),
        ).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentExecutionDraft,
        approval: SiteProductionDeploymentExecutionApproval,
    ): SiteProductionDeploymentExecutionAuthorization {
        validateDraft(draft)
        require(draft.status == SiteProductionDeploymentExecutionStatus.AWAITING_EXECUTION_APPROVAL) {
            "Blocked execution draft cannot be approved"
        }
        require(approval.confirmed) { "Production deployment execution requires explicit confirmation" }
        require(sha256.matches(approval.executionApprovalChallengeSha256)) {
            "Execution approval challenge SHA-256 is invalid"
        }
        require(approval.executionApprovalChallengeSha256 == draft.executionApprovalChallengeSha256) {
            "Execution approval is stale or bound to a different execution attempt"
        }

        val base = SiteProductionDeploymentExecutionAuthorization(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentExecutionStatus.AUTHORIZED_FOR_COORDINATOR_HANDOFF,
            realServerMutationEnabled = false,
            authorizesTransport = false,
            authorizesCoordinatorHandoff = true,
            requiresRuntimeMutationEnablement = true,
            executionAttemptId = draft.executionAttemptId,
            readyRecordSha256 = draft.readyRecordSha256,
            readinessSha256 = draft.readinessSha256,
            deploymentPlanSha256 = draft.deploymentPlanSha256,
            preflightSha256 = draft.preflightSha256,
            exportPlanSha256 = draft.exportPlanSha256,
            sourceTreeSha256 = draft.sourceTreeSha256,
            coordinatorRequestSha256 = draft.coordinatorRequestSha256,
            capabilityProfileSha256 = draft.capabilityProfileSha256,
            candidateTransportAuthorizationSha256 = draft.candidateTransportAuthorizationSha256,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            evidenceExpiresAtEpochMillis = draft.evidenceExpiresAtEpochMillis,
            executionApprovalChallengeSha256 = draft.executionApprovalChallengeSha256,
            executionAuthorizationSha256 = "",
        )
        return base.copy(
            executionAuthorizationSha256 = executionAuthorizationSha256(base),
        ).also(::validateAuthorization)
    }

    fun validateForCoordinatorHandoff(
        authorization: SiteProductionDeploymentExecutionAuthorization,
        request: SiteProductionDeploymentExecutionRequest,
    ) {
        validateAuthorization(authorization)
        val rebuilt = prepare(request)
        require(rebuilt.status == SiteProductionDeploymentExecutionStatus.AWAITING_EXECUTION_APPROVAL) {
            "Current execution request is no longer eligible for coordinator handoff"
        }
        require(authorization.executionAttemptId == rebuilt.executionAttemptId) { "Execution attempt id changed" }
        require(authorization.readyRecordSha256 == rebuilt.readyRecordSha256) { "Ready record changed" }
        require(authorization.readinessSha256 == rebuilt.readinessSha256) { "Readiness evidence changed" }
        require(authorization.deploymentPlanSha256 == rebuilt.deploymentPlanSha256) { "Deployment plan changed" }
        require(authorization.preflightSha256 == rebuilt.preflightSha256) { "Preflight evidence changed" }
        require(authorization.exportPlanSha256 == rebuilt.exportPlanSha256) { "Export plan changed" }
        require(authorization.sourceTreeSha256 == rebuilt.sourceTreeSha256) { "Source tree changed" }
        require(authorization.coordinatorRequestSha256 == rebuilt.coordinatorRequestSha256) { "Coordinator request changed" }
        require(authorization.capabilityProfileSha256 == rebuilt.capabilityProfileSha256) { "Capability profile changed" }
        require(authorization.candidateTransportAuthorizationSha256 == rebuilt.candidateTransportAuthorizationSha256) {
            "Candidate transport authorization changed"
        }
        require(authorization.executionApprovalChallengeSha256 == rebuilt.executionApprovalChallengeSha256) {
            "Execution approval challenge changed"
        }
        require(request.evaluatedAtEpochMillis <= authorization.evidenceExpiresAtEpochMillis) {
            "Execution authorization evidence expired"
        }
        require(authorization.authorizesCoordinatorHandoff) { "Execution authorization does not permit coordinator handoff" }
        require(!authorization.authorizesTransport) { "Execution boundary must not directly authorize transport" }
        require(!authorization.realServerMutationEnabled) { "Execution boundary must not enable real-server mutation" }
        require(authorization.requiresRuntimeMutationEnablement) {
            "Execution authorization must still require separate runtime mutation enablement"
        }
    }

    private fun safeExpiry(observedAtEpochMillis: Long, maxAgeMillis: Long): Long {
        require(observedAtEpochMillis >= 0L) { "Observation time must be non-negative" }
        require(maxAgeMillis > 0L) { "Observation max age must be positive" }
        require(observedAtEpochMillis <= Long.MAX_VALUE - maxAgeMillis) { "Observation expiry overflows Long" }
        return observedAtEpochMillis + maxAgeMillis
    }

    private fun coordinatorRequestSha256(request: SiteDeploymentCoordinatorRequest): String {
        val normalizedLocalOutputRoot = request.localOutputRoot.normalize().toString().replace('\\', '/')
        val remote = request.remoteRequest
        val certificateDomain = remote.certificateReuse.requestedDomain?.let(SiteRemoteDeployPolicy::normalizeDomain) ?: ""
        val canonical = buildString {
            append("exportPlanSha256=").append(request.exportPlan.manifest.planSha256).append('\n')
            append("sourceTreeSha256=").append(request.exportPlan.manifest.sourceTreeSha256).append('\n')
            append("localOutputRoot=").append(normalizedLocalOutputRoot).append('\n')
            append("remoteHostIdentity=").append(remote.remoteHostIdentity).append('\n')
            append("targetRoot=").append(remote.targetRoot).append('\n')
            append("owner=").append(remote.owner).append('\n')
            append("group=").append(remote.group).append('\n')
            append("directoryMode=").append(remote.directoryMode).append('\n')
            append("fileMode=").append(remote.fileMode).append('\n')
            append("existingTargetPolicy=").append(remote.existingTargetPolicy.name).append('\n')
            append("certificateMode=").append(remote.certificateReuse.mode.name).append('\n')
            append("certificateDomain=").append(certificateDomain).append('\n')
            append("trustedServerKeySha256=").append(request.trust.expectedServerKeySha256).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun executionApprovalChallengeSha256(
        request: SiteProductionDeploymentExecutionRequest,
        coordinatorRequestSha256: String,
        capabilityProfileSha256: String,
        candidateTransportAuthorizationSha256: String,
        evidenceExpiresAtEpochMillis: Long,
    ): String {
        val canonical = buildString {
            append("contractVersion=").append(CONTRACT_VERSION).append('\n')
            append("executionAttemptId=").append(request.executionAttemptId).append('\n')
            append("readyRecordSha256=").append(request.readyRecord.approvalRecordSha256).append('\n')
            append("readinessSha256=").append(request.readyRecord.readinessSha256).append('\n')
            append("deploymentPlanSha256=").append(request.readyRecord.deploymentPlanSha256).append('\n')
            append("preflightSha256=").append(request.readyRecord.preflightSha256).append('\n')
            append("exportPlanSha256=").append(request.readyRecord.exportPlanSha256).append('\n')
            append("sourceTreeSha256=").append(request.readyRecord.sourceTreeSha256).append('\n')
            append("coordinatorRequestSha256=").append(coordinatorRequestSha256).append('\n')
            append("capabilityProfileSha256=").append(capabilityProfileSha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(candidateTransportAuthorizationSha256).append('\n')
            append("evaluatedAtEpochMillis=").append(request.evaluatedAtEpochMillis).append('\n')
            append("evidenceExpiresAtEpochMillis=").append(evidenceExpiresAtEpochMillis).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun validateDraft(draft: SiteProductionDeploymentExecutionDraft) {
        require(draft.contractVersion == CONTRACT_VERSION) { "Unsupported production execution contract version" }
        require(!draft.realServerMutationEnabled) { "Execution boundary must never enable real-server mutation" }
        require(!draft.authorizesTransport) { "Execution boundary must never directly authorize transport" }
        require(!draft.authorizesCoordinatorHandoff) { "Execution draft cannot authorize coordinator handoff" }
        require(draft.requiresRuntimeMutationEnablement) { "Execution draft must require runtime mutation enablement" }
        require(executionAttemptId.matches(draft.executionAttemptId)) { "Execution draft attempt id is invalid" }
        listOf(
            draft.readyRecordSha256,
            draft.readinessSha256,
            draft.deploymentPlanSha256,
            draft.preflightSha256,
            draft.exportPlanSha256,
            draft.sourceTreeSha256,
            draft.coordinatorRequestSha256,
            draft.capabilityProfileSha256,
            draft.candidateTransportAuthorizationSha256,
            draft.executionApprovalChallengeSha256,
            draft.executionDraftSha256,
        ).forEach { require(sha256.matches(it)) { "Execution draft contains invalid SHA-256 evidence" } }
        require(draft.evaluatedAtEpochMillis >= 0L) { "Execution draft evaluation time is invalid" }
        require(draft.evidenceExpiresAtEpochMillis >= 0L) { "Execution draft expiry time is invalid" }
        val expectedStatus = if (draft.blockers.isEmpty()) {
            SiteProductionDeploymentExecutionStatus.AWAITING_EXECUTION_APPROVAL
        } else {
            SiteProductionDeploymentExecutionStatus.BLOCKED
        }
        require(draft.status == expectedStatus) { "Execution draft status does not match blockers" }
        require(draft.executionDraftSha256 == executionDraftSha256(draft.copy(executionDraftSha256 = ""))) {
            "Execution draft SHA-256 mismatch"
        }
    }

    private fun validateAuthorization(authorization: SiteProductionDeploymentExecutionAuthorization) {
        require(authorization.contractVersion == CONTRACT_VERSION) { "Unsupported execution authorization contract version" }
        require(authorization.status == SiteProductionDeploymentExecutionStatus.AUTHORIZED_FOR_COORDINATOR_HANDOFF) {
            "Execution authorization has invalid status"
        }
        require(!authorization.realServerMutationEnabled) { "Execution authorization must not enable real-server mutation" }
        require(!authorization.authorizesTransport) { "Execution authorization must not directly authorize transport" }
        require(authorization.authorizesCoordinatorHandoff) { "Execution authorization must permit exact coordinator handoff" }
        require(authorization.requiresRuntimeMutationEnablement) {
            "Execution authorization must require separate runtime mutation enablement"
        }
        require(executionAttemptId.matches(authorization.executionAttemptId)) { "Execution authorization attempt id is invalid" }
        listOf(
            authorization.readyRecordSha256,
            authorization.readinessSha256,
            authorization.deploymentPlanSha256,
            authorization.preflightSha256,
            authorization.exportPlanSha256,
            authorization.sourceTreeSha256,
            authorization.coordinatorRequestSha256,
            authorization.capabilityProfileSha256,
            authorization.candidateTransportAuthorizationSha256,
            authorization.executionApprovalChallengeSha256,
            authorization.executionAuthorizationSha256,
        ).forEach { require(sha256.matches(it)) { "Execution authorization contains invalid SHA-256 evidence" } }
        require(authorization.evaluatedAtEpochMillis <= authorization.evidenceExpiresAtEpochMillis) {
            "Execution authorization was issued from expired evidence"
        }
        require(
            authorization.executionAuthorizationSha256 == executionAuthorizationSha256(
                authorization.copy(executionAuthorizationSha256 = ""),
            ),
        ) { "Execution authorization SHA-256 mismatch" }
    }

    private fun executionDraftSha256(draftWithoutSha: SiteProductionDeploymentExecutionDraft): String {
        val canonical = buildString {
            append("contractVersion=").append(draftWithoutSha.contractVersion).append('\n')
            append("status=").append(draftWithoutSha.status.name).append('\n')
            append("realServerMutationEnabled=").append(draftWithoutSha.realServerMutationEnabled).append('\n')
            append("authorizesTransport=").append(draftWithoutSha.authorizesTransport).append('\n')
            append("authorizesCoordinatorHandoff=").append(draftWithoutSha.authorizesCoordinatorHandoff).append('\n')
            append("requiresRuntimeMutationEnablement=").append(draftWithoutSha.requiresRuntimeMutationEnablement).append('\n')
            append("executionAttemptId=").append(draftWithoutSha.executionAttemptId).append('\n')
            append("readyRecordSha256=").append(draftWithoutSha.readyRecordSha256).append('\n')
            append("readinessSha256=").append(draftWithoutSha.readinessSha256).append('\n')
            append("deploymentPlanSha256=").append(draftWithoutSha.deploymentPlanSha256).append('\n')
            append("preflightSha256=").append(draftWithoutSha.preflightSha256).append('\n')
            append("exportPlanSha256=").append(draftWithoutSha.exportPlanSha256).append('\n')
            append("sourceTreeSha256=").append(draftWithoutSha.sourceTreeSha256).append('\n')
            append("coordinatorRequestSha256=").append(draftWithoutSha.coordinatorRequestSha256).append('\n')
            append("capabilityProfileSha256=").append(draftWithoutSha.capabilityProfileSha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(draftWithoutSha.candidateTransportAuthorizationSha256).append('\n')
            append("evaluatedAtEpochMillis=").append(draftWithoutSha.evaluatedAtEpochMillis).append('\n')
            append("evidenceExpiresAtEpochMillis=").append(draftWithoutSha.evidenceExpiresAtEpochMillis).append('\n')
            append("executionApprovalChallengeSha256=").append(draftWithoutSha.executionApprovalChallengeSha256).append('\n')
            draftWithoutSha.blockers.forEach { blocker ->
                append("blocker=").append(blocker.code).append('\u0000').append(blocker.detail).append('\n')
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun executionAuthorizationSha256(
        authorizationWithoutSha: SiteProductionDeploymentExecutionAuthorization,
    ): String {
        val canonical = buildString {
            append("contractVersion=").append(authorizationWithoutSha.contractVersion).append('\n')
            append("status=").append(authorizationWithoutSha.status.name).append('\n')
            append("realServerMutationEnabled=").append(authorizationWithoutSha.realServerMutationEnabled).append('\n')
            append("authorizesTransport=").append(authorizationWithoutSha.authorizesTransport).append('\n')
            append("authorizesCoordinatorHandoff=").append(authorizationWithoutSha.authorizesCoordinatorHandoff).append('\n')
            append("requiresRuntimeMutationEnablement=").append(authorizationWithoutSha.requiresRuntimeMutationEnablement).append('\n')
            append("executionAttemptId=").append(authorizationWithoutSha.executionAttemptId).append('\n')
            append("readyRecordSha256=").append(authorizationWithoutSha.readyRecordSha256).append('\n')
            append("readinessSha256=").append(authorizationWithoutSha.readinessSha256).append('\n')
            append("deploymentPlanSha256=").append(authorizationWithoutSha.deploymentPlanSha256).append('\n')
            append("preflightSha256=").append(authorizationWithoutSha.preflightSha256).append('\n')
            append("exportPlanSha256=").append(authorizationWithoutSha.exportPlanSha256).append('\n')
            append("sourceTreeSha256=").append(authorizationWithoutSha.sourceTreeSha256).append('\n')
            append("coordinatorRequestSha256=").append(authorizationWithoutSha.coordinatorRequestSha256).append('\n')
            append("capabilityProfileSha256=").append(authorizationWithoutSha.capabilityProfileSha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(authorizationWithoutSha.candidateTransportAuthorizationSha256).append('\n')
            append("evaluatedAtEpochMillis=").append(authorizationWithoutSha.evaluatedAtEpochMillis).append('\n')
            append("evidenceExpiresAtEpochMillis=").append(authorizationWithoutSha.evidenceExpiresAtEpochMillis).append('\n')
            append("executionApprovalChallengeSha256=").append(authorizationWithoutSha.executionApprovalChallengeSha256).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }
}

package com.velumtegra.xuimobile.core.site

object SiteProductionDeploymentRuntimeMutationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_PERMIT_LIFETIME_MILLIS: Long = 60_000L

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        request: SiteProductionDeploymentRuntimeMutationRequest,
    ): SiteProductionDeploymentRuntimeMutationDraft {
        require(canonicalId.matches(request.coordinatorInvocationId)) {
            "Coordinator invocation id must be a canonical 8..128 character identifier"
        }
        require(canonicalId.matches(request.runtimeIdentity.runtimeSessionId)) {
            "Runtime session id must be a canonical 8..128 character identifier"
        }
        require(request.evaluatedAtEpochMillis >= 0L) { "Runtime mutation evaluation time must be non-negative" }
        require(request.requestedPermitLifetimeMillis in 1L..MAX_PERMIT_LIFETIME_MILLIS) {
            "Runtime mutation permit lifetime must be within 1..$MAX_PERMIT_LIFETIME_MILLIS ms"
        }

        SiteProductionDeploymentExecutionBoundary.validateForCoordinatorHandoff(
            request.executionAuthorization,
            request.executionRequest,
        )
        val executionAuthorization = request.executionAuthorization
        require(executionAuthorization.authorizesCoordinatorHandoff) {
            "Execution authorization does not permit coordinator handoff"
        }
        require(executionAuthorization.requiresRuntimeMutationEnablement) {
            "Execution authorization does not require this runtime mutation gate"
        }
        require(!executionAuthorization.realServerMutationEnabled) {
            "Execution authorization must not already enable real-server mutation"
        }
        require(!executionAuthorization.authorizesTransport) {
            "Execution authorization must not directly authorize transport"
        }
        require(request.evaluatedAtEpochMillis >= executionAuthorization.evaluatedAtEpochMillis) {
            "Runtime mutation evaluation cannot predate execution authorization"
        }

        val runtimeIdentitySha256 = runtimeIdentitySha256(request.runtimeIdentity)
        val expectedCapabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(
            request.executionRequest.transportCapabilities,
        )
        require(request.runtimeIdentity.remoteHostIdentity == request.executionRequest.readyRecord.remoteHostIdentity) {
            "Runtime host identity differs from approved production host"
        }
        require(
            request.runtimeIdentity.transportImplementationId ==
                request.executionRequest.transportCapabilities.implementationId,
        ) { "Runtime transport implementation differs from the execution authorization input" }
        require(request.runtimeIdentity.capabilityProfileSha256 == expectedCapabilityProfileSha256) {
            "Runtime capability profile digest differs from current transport capabilities"
        }
        require(request.runtimeIdentity.capabilityProfileSha256 == executionAuthorization.capabilityProfileSha256) {
            "Runtime capability profile differs from execution authorization"
        }

        val requestedExpiry = safeAdd(
            request.evaluatedAtEpochMillis,
            request.requestedPermitLifetimeMillis,
            "Runtime mutation permit expiry overflows Long",
        )
        val permitExpiresAt = minOf(
            executionAuthorization.evidenceExpiresAtEpochMillis,
            requestedExpiry,
        )
        val blockers = buildList {
            if (request.evaluatedAtEpochMillis > executionAuthorization.evidenceExpiresAtEpochMillis) {
                add(
                    SiteProductionDeploymentRuntimeMutationBlocker(
                        code = "EXECUTION_EVIDENCE_STALE",
                        detail = "Execution authorization evidence expired before runtime mutation enablement",
                    ),
                )
            }
            if (permitExpiresAt <= request.evaluatedAtEpochMillis) {
                add(
                    SiteProductionDeploymentRuntimeMutationBlocker(
                        code = "NO_SAFE_MUTATION_WINDOW",
                        detail = "No positive runtime mutation window remains after evidence expiry",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentRuntimeMutationStatus.AWAITING_RUNTIME_MUTATION_APPROVAL
        } else {
            SiteProductionDeploymentRuntimeMutationStatus.BLOCKED
        }
        val challenge = runtimeMutationApprovalChallengeSha256(
            request = request,
            runtimeIdentitySha256 = runtimeIdentitySha256,
            permitExpiresAtEpochMillis = permitExpiresAt,
        )
        val base = SiteProductionDeploymentRuntimeMutationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            realServerMutationEnabled = false,
            authorizesTransport = false,
            authorizesCoordinatorInvocation = false,
            requiresAtomicOneShotConsumption = true,
            executionAttemptId = executionAuthorization.executionAttemptId,
            coordinatorInvocationId = request.coordinatorInvocationId,
            executionAuthorizationSha256 = executionAuthorization.executionAuthorizationSha256,
            readyRecordSha256 = executionAuthorization.readyRecordSha256,
            coordinatorRequestSha256 = executionAuthorization.coordinatorRequestSha256,
            capabilityProfileSha256 = executionAuthorization.capabilityProfileSha256,
            candidateTransportAuthorizationSha256 = executionAuthorization.candidateTransportAuthorizationSha256,
            runtimeIdentitySha256 = runtimeIdentitySha256,
            evaluatedAtEpochMillis = request.evaluatedAtEpochMillis,
            readinessEvidenceExpiresAtEpochMillis = executionAuthorization.evidenceExpiresAtEpochMillis,
            permitExpiresAtEpochMillis = permitExpiresAt,
            blockers = blockers,
            runtimeMutationApprovalChallengeSha256 = challenge,
            runtimeMutationDraftSha256 = "",
        )
        return base.copy(
            runtimeMutationDraftSha256 = runtimeMutationDraftSha256(base),
        ).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentRuntimeMutationDraft,
        approval: SiteProductionDeploymentRuntimeMutationApproval,
    ): SiteProductionDeploymentRuntimeMutationPermit {
        validateDraft(draft)
        require(draft.status == SiteProductionDeploymentRuntimeMutationStatus.AWAITING_RUNTIME_MUTATION_APPROVAL) {
            "Blocked runtime mutation draft cannot be approved"
        }
        require(approval.confirmed) { "Runtime mutation enablement requires explicit confirmation" }
        require(sha256.matches(approval.runtimeMutationApprovalChallengeSha256)) {
            "Runtime mutation approval challenge SHA-256 is invalid"
        }
        require(
            approval.runtimeMutationApprovalChallengeSha256 == draft.runtimeMutationApprovalChallengeSha256,
        ) { "Runtime mutation approval is stale or bound to a different invocation" }

        val base = SiteProductionDeploymentRuntimeMutationPermit(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRuntimeMutationStatus.RUNTIME_MUTATION_PERMIT_ISSUED,
            realServerMutationEnabled = false,
            authorizesTransport = false,
            authorizesCoordinatorInvocation = false,
            requiresAtomicOneShotConsumption = true,
            executionAttemptId = draft.executionAttemptId,
            coordinatorInvocationId = draft.coordinatorInvocationId,
            executionAuthorizationSha256 = draft.executionAuthorizationSha256,
            readyRecordSha256 = draft.readyRecordSha256,
            coordinatorRequestSha256 = draft.coordinatorRequestSha256,
            capabilityProfileSha256 = draft.capabilityProfileSha256,
            candidateTransportAuthorizationSha256 = draft.candidateTransportAuthorizationSha256,
            runtimeIdentitySha256 = draft.runtimeIdentitySha256,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            readinessEvidenceExpiresAtEpochMillis = draft.readinessEvidenceExpiresAtEpochMillis,
            permitExpiresAtEpochMillis = draft.permitExpiresAtEpochMillis,
            runtimeMutationApprovalChallengeSha256 = draft.runtimeMutationApprovalChallengeSha256,
            permitSha256 = "",
        )
        return base.copy(
            permitSha256 = permitSha256(base),
        ).also(::validatePermit)
    }

    fun consumeForSingleCoordinatorInvocation(
        permit: SiteProductionDeploymentRuntimeMutationPermit,
        request: SiteProductionDeploymentRuntimeMutationRequest,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentRuntimeMutationConsumptionPort,
    ): SiteProductionDeploymentCoordinatorInvocationAuthorization {
        validatePermit(permit)
        require(consumedAtEpochMillis >= 0L) { "Runtime mutation consumption time must be non-negative" }
        require(consumedAtEpochMillis >= permit.evaluatedAtEpochMillis) {
            "Runtime mutation permit cannot be consumed before it was evaluated"
        }
        require(consumedAtEpochMillis <= permit.permitExpiresAtEpochMillis) {
            "Runtime mutation permit expired before coordinator invocation"
        }

        val rebuilt = prepare(request)
        require(rebuilt.status == SiteProductionDeploymentRuntimeMutationStatus.AWAITING_RUNTIME_MUTATION_APPROVAL) {
            "Current runtime mutation request is no longer eligible"
        }
        require(permit.executionAttemptId == rebuilt.executionAttemptId) { "Execution attempt changed" }
        require(permit.coordinatorInvocationId == rebuilt.coordinatorInvocationId) { "Coordinator invocation id changed" }
        require(permit.executionAuthorizationSha256 == rebuilt.executionAuthorizationSha256) {
            "Execution authorization changed"
        }
        require(permit.readyRecordSha256 == rebuilt.readyRecordSha256) { "Ready record changed" }
        require(permit.coordinatorRequestSha256 == rebuilt.coordinatorRequestSha256) { "Coordinator request changed" }
        require(permit.capabilityProfileSha256 == rebuilt.capabilityProfileSha256) { "Capability profile changed" }
        require(permit.candidateTransportAuthorizationSha256 == rebuilt.candidateTransportAuthorizationSha256) {
            "Candidate transport authorization changed"
        }
        require(permit.runtimeIdentitySha256 == rebuilt.runtimeIdentitySha256) { "Runtime identity changed" }
        require(permit.runtimeMutationApprovalChallengeSha256 == rebuilt.runtimeMutationApprovalChallengeSha256) {
            "Runtime mutation approval challenge changed"
        }
        require(permit.permitExpiresAtEpochMillis == rebuilt.permitExpiresAtEpochMillis) {
            "Runtime mutation permit expiry changed"
        }

        require(consumptionPort.consumeOnce(permit.permitSha256)) {
            "Runtime mutation permit was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentCoordinatorInvocationAuthorization(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRuntimeMutationStatus.AUTHORIZED_FOR_SINGLE_COORDINATOR_INVOCATION,
            realServerMutationEnabled = true,
            authorizesTransport = false,
            authorizesCoordinatorInvocation = true,
            singleUseConsumed = true,
            executionAttemptId = permit.executionAttemptId,
            coordinatorInvocationId = permit.coordinatorInvocationId,
            executionAuthorizationSha256 = permit.executionAuthorizationSha256,
            coordinatorRequestSha256 = permit.coordinatorRequestSha256,
            runtimeIdentitySha256 = permit.runtimeIdentitySha256,
            permitSha256 = permit.permitSha256,
            consumedAtEpochMillis = consumedAtEpochMillis,
            permitExpiresAtEpochMillis = permit.permitExpiresAtEpochMillis,
            invocationAuthorizationSha256 = "",
        )
        return base.copy(
            invocationAuthorizationSha256 = invocationAuthorizationSha256(base),
        ).also(::validateInvocationAuthorization)
    }

    fun validateForCoordinatorInvocation(
        authorization: SiteProductionDeploymentCoordinatorInvocationAuthorization,
        request: SiteProductionDeploymentRuntimeMutationRequest,
        invokedAtEpochMillis: Long,
    ) {
        validateInvocationAuthorization(authorization)
        require(invokedAtEpochMillis >= authorization.consumedAtEpochMillis) {
            "Coordinator invocation cannot predate runtime mutation consumption"
        }
        require(invokedAtEpochMillis <= authorization.permitExpiresAtEpochMillis) {
            "Coordinator invocation authorization expired before invocation"
        }

        val rebuilt = prepare(request)
        require(rebuilt.status == SiteProductionDeploymentRuntimeMutationStatus.AWAITING_RUNTIME_MUTATION_APPROVAL) {
            "Current runtime mutation request is no longer eligible for coordinator invocation"
        }
        require(authorization.executionAttemptId == rebuilt.executionAttemptId) { "Execution attempt changed" }
        require(authorization.coordinatorInvocationId == rebuilt.coordinatorInvocationId) {
            "Coordinator invocation id changed"
        }
        require(authorization.executionAuthorizationSha256 == rebuilt.executionAuthorizationSha256) {
            "Execution authorization changed"
        }
        require(authorization.coordinatorRequestSha256 == rebuilt.coordinatorRequestSha256) {
            "Coordinator request changed"
        }
        require(authorization.runtimeIdentitySha256 == rebuilt.runtimeIdentitySha256) { "Runtime identity changed" }
        require(authorization.authorizesCoordinatorInvocation) {
            "Coordinator invocation authorization does not authorize invocation"
        }
        require(!authorization.authorizesTransport) {
            "Coordinator invocation authorization must not directly authorize transport"
        }
        require(authorization.realServerMutationEnabled) {
            "Coordinator invocation authorization is not mutation-enabled"
        }
        require(authorization.singleUseConsumed) {
            "Coordinator invocation authorization must originate from one-shot permit consumption"
        }
    }

    private fun validateDraft(draft: SiteProductionDeploymentRuntimeMutationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION) { "Unsupported runtime mutation contract version" }
        require(!draft.realServerMutationEnabled) { "Runtime mutation draft must not enable real-server mutation" }
        require(!draft.authorizesTransport) { "Runtime mutation draft must not authorize transport" }
        require(!draft.authorizesCoordinatorInvocation) { "Runtime mutation draft must not authorize coordinator invocation" }
        require(draft.requiresAtomicOneShotConsumption) { "Runtime mutation draft must require atomic one-shot consumption" }
        require(canonicalId.matches(draft.executionAttemptId)) { "Runtime mutation draft execution attempt id is invalid" }
        require(canonicalId.matches(draft.coordinatorInvocationId)) { "Runtime mutation draft invocation id is invalid" }
        validateHashes(
            draft.executionAuthorizationSha256,
            draft.readyRecordSha256,
            draft.coordinatorRequestSha256,
            draft.capabilityProfileSha256,
            draft.candidateTransportAuthorizationSha256,
            draft.runtimeIdentitySha256,
            draft.runtimeMutationApprovalChallengeSha256,
            draft.runtimeMutationDraftSha256,
        )
        require(draft.evaluatedAtEpochMillis >= 0L) { "Runtime mutation draft evaluation time is invalid" }
        require(draft.readinessEvidenceExpiresAtEpochMillis >= 0L) { "Runtime mutation evidence expiry is invalid" }
        require(draft.permitExpiresAtEpochMillis >= 0L) { "Runtime mutation permit expiry is invalid" }
        require(draft.permitExpiresAtEpochMillis <= draft.readinessEvidenceExpiresAtEpochMillis) {
            "Runtime mutation permit cannot outlive readiness evidence"
        }
        val expectedStatus = if (draft.blockers.isEmpty()) {
            SiteProductionDeploymentRuntimeMutationStatus.AWAITING_RUNTIME_MUTATION_APPROVAL
        } else {
            SiteProductionDeploymentRuntimeMutationStatus.BLOCKED
        }
        require(draft.status == expectedStatus) { "Runtime mutation draft status does not match blockers" }
        require(
            draft.runtimeMutationDraftSha256 == runtimeMutationDraftSha256(
                draft.copy(runtimeMutationDraftSha256 = ""),
            ),
        ) { "Runtime mutation draft SHA-256 mismatch" }
    }

    private fun validatePermit(permit: SiteProductionDeploymentRuntimeMutationPermit) {
        require(permit.contractVersion == CONTRACT_VERSION) { "Unsupported runtime mutation permit contract version" }
        require(permit.status == SiteProductionDeploymentRuntimeMutationStatus.RUNTIME_MUTATION_PERMIT_ISSUED) {
            "Runtime mutation permit has invalid status"
        }
        require(!permit.realServerMutationEnabled) {
            "Permit issuance alone must not enable real-server mutation"
        }
        require(!permit.authorizesTransport) { "Runtime mutation permit must not directly authorize transport" }
        require(!permit.authorizesCoordinatorInvocation) {
            "Runtime mutation permit must be atomically consumed before coordinator invocation"
        }
        require(permit.requiresAtomicOneShotConsumption) {
            "Runtime mutation permit must require atomic one-shot consumption"
        }
        require(canonicalId.matches(permit.executionAttemptId)) { "Runtime mutation permit execution attempt id is invalid" }
        require(canonicalId.matches(permit.coordinatorInvocationId)) { "Runtime mutation permit invocation id is invalid" }
        validateHashes(
            permit.executionAuthorizationSha256,
            permit.readyRecordSha256,
            permit.coordinatorRequestSha256,
            permit.capabilityProfileSha256,
            permit.candidateTransportAuthorizationSha256,
            permit.runtimeIdentitySha256,
            permit.runtimeMutationApprovalChallengeSha256,
            permit.permitSha256,
        )
        require(permit.evaluatedAtEpochMillis <= permit.permitExpiresAtEpochMillis) {
            "Runtime mutation permit has invalid expiry"
        }
        require(permit.permitExpiresAtEpochMillis <= permit.readinessEvidenceExpiresAtEpochMillis) {
            "Runtime mutation permit outlives readiness evidence"
        }
        require(permit.permitSha256 == permitSha256(permit.copy(permitSha256 = ""))) {
            "Runtime mutation permit SHA-256 mismatch"
        }
    }

    private fun validateInvocationAuthorization(
        authorization: SiteProductionDeploymentCoordinatorInvocationAuthorization,
    ) {
        require(authorization.contractVersion == CONTRACT_VERSION) { "Unsupported coordinator invocation contract version" }
        require(
            authorization.status == SiteProductionDeploymentRuntimeMutationStatus.AUTHORIZED_FOR_SINGLE_COORDINATOR_INVOCATION,
        ) { "Coordinator invocation authorization has invalid status" }
        require(authorization.realServerMutationEnabled) {
            "Consumed runtime mutation authorization must enable its exact coordinator invocation"
        }
        require(!authorization.authorizesTransport) {
            "Coordinator invocation authorization must not directly authorize transport"
        }
        require(authorization.authorizesCoordinatorInvocation) {
            "Consumed runtime mutation authorization must authorize the exact coordinator invocation"
        }
        require(authorization.singleUseConsumed) { "Coordinator invocation authorization must record one-shot consumption" }
        validateHashes(
            authorization.executionAuthorizationSha256,
            authorization.coordinatorRequestSha256,
            authorization.runtimeIdentitySha256,
            authorization.permitSha256,
            authorization.invocationAuthorizationSha256,
        )
        require(authorization.consumedAtEpochMillis <= authorization.permitExpiresAtEpochMillis) {
            "Coordinator invocation authorization was consumed after permit expiry"
        }
        require(
            authorization.invocationAuthorizationSha256 == invocationAuthorizationSha256(
                authorization.copy(invocationAuthorizationSha256 = ""),
            ),
        ) { "Coordinator invocation authorization SHA-256 mismatch" }
    }

    private fun validateHashes(vararg values: String) {
        values.forEach { require(sha256.matches(it)) { "Runtime mutation boundary contains invalid SHA-256 evidence" } }
    }

    private fun runtimeIdentitySha256(identity: SiteProductionDeploymentRuntimeIdentity): String {
        require(canonicalId.matches(identity.runtimeSessionId)) { "Runtime session id is invalid" }
        require(identity.remoteHostIdentity.isNotBlank()) { "Runtime remote host identity is blank" }
        require(identity.transportImplementationId.isNotBlank()) { "Runtime transport implementation id is blank" }
        require(sha256.matches(identity.capabilityProfileSha256)) { "Runtime capability profile SHA-256 is invalid" }
        val canonical = buildString {
            append("runtimeSessionId=").append(identity.runtimeSessionId).append('\n')
            append("remoteHostIdentity=").append(identity.remoteHostIdentity).append('\n')
            append("transportImplementationId=").append(identity.transportImplementationId).append('\n')
            append("capabilityProfileSha256=").append(identity.capabilityProfileSha256).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun runtimeMutationApprovalChallengeSha256(
        request: SiteProductionDeploymentRuntimeMutationRequest,
        runtimeIdentitySha256: String,
        permitExpiresAtEpochMillis: Long,
    ): String {
        val authorization = request.executionAuthorization
        val canonical = buildString {
            append("contractVersion=").append(CONTRACT_VERSION).append('\n')
            append("executionAttemptId=").append(authorization.executionAttemptId).append('\n')
            append("coordinatorInvocationId=").append(request.coordinatorInvocationId).append('\n')
            append("executionAuthorizationSha256=").append(authorization.executionAuthorizationSha256).append('\n')
            append("readyRecordSha256=").append(authorization.readyRecordSha256).append('\n')
            append("coordinatorRequestSha256=").append(authorization.coordinatorRequestSha256).append('\n')
            append("capabilityProfileSha256=").append(authorization.capabilityProfileSha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(authorization.candidateTransportAuthorizationSha256).append('\n')
            append("runtimeIdentitySha256=").append(runtimeIdentitySha256).append('\n')
            append("evaluatedAtEpochMillis=").append(request.evaluatedAtEpochMillis).append('\n')
            append("requestedPermitLifetimeMillis=").append(request.requestedPermitLifetimeMillis).append('\n')
            append("readinessEvidenceExpiresAtEpochMillis=").append(authorization.evidenceExpiresAtEpochMillis).append('\n')
            append("permitExpiresAtEpochMillis=").append(permitExpiresAtEpochMillis).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun runtimeMutationDraftSha256(
        draftWithoutSha: SiteProductionDeploymentRuntimeMutationDraft,
    ): String {
        val canonical = buildString {
            append("contractVersion=").append(draftWithoutSha.contractVersion).append('\n')
            append("status=").append(draftWithoutSha.status.name).append('\n')
            append("realServerMutationEnabled=").append(draftWithoutSha.realServerMutationEnabled).append('\n')
            append("authorizesTransport=").append(draftWithoutSha.authorizesTransport).append('\n')
            append("authorizesCoordinatorInvocation=").append(draftWithoutSha.authorizesCoordinatorInvocation).append('\n')
            append("requiresAtomicOneShotConsumption=").append(draftWithoutSha.requiresAtomicOneShotConsumption).append('\n')
            append("executionAttemptId=").append(draftWithoutSha.executionAttemptId).append('\n')
            append("coordinatorInvocationId=").append(draftWithoutSha.coordinatorInvocationId).append('\n')
            append("executionAuthorizationSha256=").append(draftWithoutSha.executionAuthorizationSha256).append('\n')
            append("readyRecordSha256=").append(draftWithoutSha.readyRecordSha256).append('\n')
            append("coordinatorRequestSha256=").append(draftWithoutSha.coordinatorRequestSha256).append('\n')
            append("capabilityProfileSha256=").append(draftWithoutSha.capabilityProfileSha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(draftWithoutSha.candidateTransportAuthorizationSha256).append('\n')
            append("runtimeIdentitySha256=").append(draftWithoutSha.runtimeIdentitySha256).append('\n')
            append("evaluatedAtEpochMillis=").append(draftWithoutSha.evaluatedAtEpochMillis).append('\n')
            append("readinessEvidenceExpiresAtEpochMillis=").append(draftWithoutSha.readinessEvidenceExpiresAtEpochMillis).append('\n')
            append("permitExpiresAtEpochMillis=").append(draftWithoutSha.permitExpiresAtEpochMillis).append('\n')
            append("runtimeMutationApprovalChallengeSha256=").append(draftWithoutSha.runtimeMutationApprovalChallengeSha256).append('\n')
            draftWithoutSha.blockers.forEach { blocker ->
                append("blocker=").append(blocker.code).append('\u0000').append(blocker.detail).append('\n')
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun permitSha256(permitWithoutSha: SiteProductionDeploymentRuntimeMutationPermit): String {
        val canonical = buildString {
            append("contractVersion=").append(permitWithoutSha.contractVersion).append('\n')
            append("status=").append(permitWithoutSha.status.name).append('\n')
            append("realServerMutationEnabled=").append(permitWithoutSha.realServerMutationEnabled).append('\n')
            append("authorizesTransport=").append(permitWithoutSha.authorizesTransport).append('\n')
            append("authorizesCoordinatorInvocation=").append(permitWithoutSha.authorizesCoordinatorInvocation).append('\n')
            append("requiresAtomicOneShotConsumption=").append(permitWithoutSha.requiresAtomicOneShotConsumption).append('\n')
            append("executionAttemptId=").append(permitWithoutSha.executionAttemptId).append('\n')
            append("coordinatorInvocationId=").append(permitWithoutSha.coordinatorInvocationId).append('\n')
            append("executionAuthorizationSha256=").append(permitWithoutSha.executionAuthorizationSha256).append('\n')
            append("readyRecordSha256=").append(permitWithoutSha.readyRecordSha256).append('\n')
            append("coordinatorRequestSha256=").append(permitWithoutSha.coordinatorRequestSha256).append('\n')
            append("capabilityProfileSha256=").append(permitWithoutSha.capabilityProfileSha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(permitWithoutSha.candidateTransportAuthorizationSha256).append('\n')
            append("runtimeIdentitySha256=").append(permitWithoutSha.runtimeIdentitySha256).append('\n')
            append("evaluatedAtEpochMillis=").append(permitWithoutSha.evaluatedAtEpochMillis).append('\n')
            append("readinessEvidenceExpiresAtEpochMillis=").append(permitWithoutSha.readinessEvidenceExpiresAtEpochMillis).append('\n')
            append("permitExpiresAtEpochMillis=").append(permitWithoutSha.permitExpiresAtEpochMillis).append('\n')
            append("runtimeMutationApprovalChallengeSha256=").append(permitWithoutSha.runtimeMutationApprovalChallengeSha256).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun invocationAuthorizationSha256(
        authorizationWithoutSha: SiteProductionDeploymentCoordinatorInvocationAuthorization,
    ): String {
        val canonical = buildString {
            append("contractVersion=").append(authorizationWithoutSha.contractVersion).append('\n')
            append("status=").append(authorizationWithoutSha.status.name).append('\n')
            append("realServerMutationEnabled=").append(authorizationWithoutSha.realServerMutationEnabled).append('\n')
            append("authorizesTransport=").append(authorizationWithoutSha.authorizesTransport).append('\n')
            append("authorizesCoordinatorInvocation=").append(authorizationWithoutSha.authorizesCoordinatorInvocation).append('\n')
            append("singleUseConsumed=").append(authorizationWithoutSha.singleUseConsumed).append('\n')
            append("executionAttemptId=").append(authorizationWithoutSha.executionAttemptId).append('\n')
            append("coordinatorInvocationId=").append(authorizationWithoutSha.coordinatorInvocationId).append('\n')
            append("executionAuthorizationSha256=").append(authorizationWithoutSha.executionAuthorizationSha256).append('\n')
            append("coordinatorRequestSha256=").append(authorizationWithoutSha.coordinatorRequestSha256).append('\n')
            append("runtimeIdentitySha256=").append(authorizationWithoutSha.runtimeIdentitySha256).append('\n')
            append("permitSha256=").append(authorizationWithoutSha.permitSha256).append('\n')
            append("consumedAtEpochMillis=").append(authorizationWithoutSha.consumedAtEpochMillis).append('\n')
            append("permitExpiresAtEpochMillis=").append(authorizationWithoutSha.permitExpiresAtEpochMillis).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun safeAdd(left: Long, right: Long, message: String): Long {
        require(right >= 0L) { "Duration must be non-negative" }
        require(left <= Long.MAX_VALUE - right) { message }
        return left + right
    }
}

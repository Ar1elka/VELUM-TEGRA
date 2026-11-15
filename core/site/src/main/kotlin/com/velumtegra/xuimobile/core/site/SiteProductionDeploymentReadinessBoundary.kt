package com.velumtegra.xuimobile.core.site

object SiteProductionDeploymentReadinessBoundary {
    const val CONTRACT_VERSION: Int = 2

    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun prepare(request: SiteProductionDeploymentReadinessRequest): SiteProductionDeploymentReadinessDraft {
        SiteLocalExportPolicy.validatePlan(request.exportPlan)
        SiteRemoteDeployPolicy.validateRequest(request.remoteRequest)
        SiteRemotePreflightPolicy.validateTrust(request.trust)

        val normalizedIntent = normalizeIntent(request.serviceBindingIntent)
        val normalizedObservation = normalizeObservation(request.serviceBindingObservation)
        validateFreshnessPolicy(request.freshnessPolicy)
        validateObservationTimestamp(request.remoteObservationObservedAtEpochMillis, request.freshnessPolicy.evaluatedAtEpochMillis)
        validateObservationTimestamp(normalizedObservation.observedAtEpochMillis, request.freshnessPolicy.evaluatedAtEpochMillis)
        validateCertificateIntent(request.remoteRequest, normalizedIntent)

        val plan = SiteRemoteDeployBoundary.prepare(
            exportPlan = request.exportPlan,
            localReceipt = request.localReceipt,
            request = request.remoteRequest,
        )
        val preflight = SiteRemoteDeployPreflight.evaluate(
            plan = plan,
            trust = request.trust,
            observation = request.remoteObservation,
        )
        val serviceChecks = serviceBindingChecks(
            plan = plan,
            trust = request.trust,
            intent = normalizedIntent,
            observation = normalizedObservation,
            readinessMode = request.serviceBindingReadinessMode,
        )
        val blockers = buildList {
            preflight.checks.filterNot(SiteRemotePreflightCheck::passed).forEach { check ->
                add(
                    SiteProductionReadinessBlocker(
                        scope = "REMOTE_PREFLIGHT",
                        code = check.code.name,
                        detail = check.detail,
                    ),
                )
            }
            serviceChecks.filterNot(SiteProductionServiceBindingCheck::passed).forEach { check ->
                add(
                    SiteProductionReadinessBlocker(
                        scope = "SERVICE_BINDING",
                        code = check.code.name,
                        detail = check.detail,
                    ),
                )
            }
            if (!isFresh(request.remoteObservationObservedAtEpochMillis, request.freshnessPolicy)) {
                add(
                    SiteProductionReadinessBlocker(
                        scope = "EVIDENCE_FRESHNESS",
                        code = "REMOTE_OBSERVATION_STALE",
                        detail = "Remote preflight observation is older than the allowed readiness window",
                    ),
                )
            }
            if (!isFresh(normalizedObservation.observedAtEpochMillis, request.freshnessPolicy)) {
                add(
                    SiteProductionReadinessBlocker(
                        scope = "EVIDENCE_FRESHNESS",
                        code = "SERVICE_BINDING_OBSERVATION_STALE",
                        detail = "Service-binding observation is older than the allowed readiness window",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty() && preflight.status == SiteRemotePreflightStatus.READY) {
            SiteProductionDeploymentReadinessStatus.AWAITING_OPERATOR_APPROVAL
        } else {
            SiteProductionDeploymentReadinessStatus.BLOCKED
        }
        val serviceObservationSha256 = serviceBindingObservationSha256(normalizedObservation)
        val challenge = approvalChallengeSha256(
            exportManifest = request.exportPlan.manifest,
            plan = plan,
            preflight = preflight,
            serviceBindingIntent = normalizedIntent,
            serviceBindingReadinessMode = request.serviceBindingReadinessMode,
            serviceBindingObservationSha256 = serviceObservationSha256,
            remoteObservationObservedAtEpochMillis = request.remoteObservationObservedAtEpochMillis,
            serviceBindingObservedAtEpochMillis = normalizedObservation.observedAtEpochMillis,
            freshnessPolicy = request.freshnessPolicy,
        )
        val base = SiteProductionDeploymentReadinessDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            realServerMutationEnabled = false,
            authorizesTransport = false,
            requiresSeparateExecutionAuthorization = true,
            exportManifest = request.exportPlan.manifest.copy(),
            deploymentPlan = plan,
            preflight = preflight,
            remoteObservationObservedAtEpochMillis = request.remoteObservationObservedAtEpochMillis,
            serviceBindingIntent = normalizedIntent,
            serviceBindingReadinessMode = request.serviceBindingReadinessMode,
            serviceBindingObservationSha256 = serviceObservationSha256,
            serviceBindingObservedAtEpochMillis = normalizedObservation.observedAtEpochMillis,
            freshnessPolicy = request.freshnessPolicy,
            serviceBindingChecks = serviceChecks,
            blockers = blockers,
            operatorApprovalChallengeSha256 = challenge,
            readinessSha256 = "",
        )
        return base.copy(
            readinessSha256 = readinessSha256(base),
        ).also(::validateDraft)
    }

    fun approve(
        draft: SiteProductionDeploymentReadinessDraft,
        approval: SiteProductionOperatorApproval,
    ): SiteProductionDeploymentReadyRecord {
        validateDraft(draft)
        require(draft.status == SiteProductionDeploymentReadinessStatus.AWAITING_OPERATOR_APPROVAL) {
            "Blocked production readiness cannot be operator-approved"
        }
        require(approval.confirmed) { "Production deployment requires explicit operator confirmation" }
        require(sha256.matches(approval.operatorApprovalChallengeSha256)) {
            "Operator approval challenge SHA-256 is invalid"
        }
        require(approval.operatorApprovalChallengeSha256 == draft.operatorApprovalChallengeSha256) {
            "Operator approval is stale or bound to different deployment evidence"
        }

        val base = SiteProductionDeploymentReadyRecord(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentReadinessStatus.READY_FOR_EXPLICIT_EXECUTION,
            realServerMutationEnabled = false,
            authorizesTransport = false,
            requiresSeparateExecutionAuthorization = true,
            operatorApproved = true,
            operatorApprovalChallengeSha256 = draft.operatorApprovalChallengeSha256,
            readinessSha256 = draft.readinessSha256,
            deploymentPlanSha256 = draft.deploymentPlan.deploymentPlanSha256,
            preflightSha256 = draft.preflight.preflightSha256,
            exportPlanSha256 = draft.exportManifest.planSha256,
            sourceTreeSha256 = draft.exportManifest.sourceTreeSha256,
            remoteHostIdentity = draft.deploymentPlan.remoteHostIdentity,
            targetRoot = draft.deploymentPlan.publish.targetRoot,
            stagingRoot = draft.deploymentPlan.publish.stagingRoot,
            backupRoot = draft.deploymentPlan.publish.backupRoot,
            serviceBindingDomain = draft.serviceBindingIntent.domain,
            serviceBindingPort = draft.serviceBindingIntent.port,
            serviceBindingReadinessMode = draft.serviceBindingReadinessMode,
            serviceBindingObservationSha256 = draft.serviceBindingObservationSha256,
            remoteObservationObservedAtEpochMillis = draft.remoteObservationObservedAtEpochMillis,
            serviceBindingObservedAtEpochMillis = draft.serviceBindingObservedAtEpochMillis,
            evaluatedAtEpochMillis = draft.freshnessPolicy.evaluatedAtEpochMillis,
            maxObservationAgeMillis = draft.freshnessPolicy.maxAgeMillis,
            approvalRecordSha256 = "",
        )
        return base.copy(
            approvalRecordSha256 = approvalRecordSha256(base),
        ).also(::validateReadyRecord)
    }

    private fun normalizeIntent(intent: SiteProductionServiceBindingIntent): SiteProductionServiceBindingIntent {
        require(intent.port in 1..65535) { "Production service port must be inside 1..65535" }
        return intent.copy(domain = SiteRemoteDeployPolicy.normalizeDomain(intent.domain))
    }

    private fun normalizeObservation(
        observation: SiteProductionServiceBindingObservation,
    ): SiteProductionServiceBindingObservation {
        require(observation.remoteHostIdentity.isNotBlank()) { "Observed service host identity must not be blank" }
        require(sha256.matches(observation.serverKeySha256)) { "Observed service server key SHA-256 is invalid" }
        require(observation.port in 1..65535) { "Observed service port must be inside 1..65535" }
        return observation.copy(domain = SiteRemoteDeployPolicy.normalizeDomain(observation.domain))
    }


    private fun validateFreshnessPolicy(policy: SiteProductionObservationFreshnessPolicy) {
        require(policy.evaluatedAtEpochMillis >= 0L) { "Readiness evaluation time must be non-negative" }
        require(policy.maxAgeMillis > 0L) { "Observation max age must be positive" }
    }

    private fun validateObservationTimestamp(observedAtEpochMillis: Long, evaluatedAtEpochMillis: Long) {
        require(observedAtEpochMillis >= 0L) { "Observation time must be non-negative" }
        require(observedAtEpochMillis <= evaluatedAtEpochMillis) { "Observation time cannot be in the future" }
    }

    private fun isFresh(
        observedAtEpochMillis: Long,
        policy: SiteProductionObservationFreshnessPolicy,
    ): Boolean = policy.evaluatedAtEpochMillis - observedAtEpochMillis <= policy.maxAgeMillis

    private fun validateCertificateIntent(
        remoteRequest: SiteRemoteDeployRequest,
        intent: SiteProductionServiceBindingIntent,
    ) {
        if (remoteRequest.certificateReuse.mode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN) {
            val certificateDomain = SiteRemoteDeployPolicy.normalizeDomain(
                requireNotNull(remoteRequest.certificateReuse.requestedDomain) {
                    "Certificate reuse request must contain a domain"
                },
            )
            require(certificateDomain == intent.domain) {
                "Certificate reuse domain must exactly match production service-binding domain"
            }
        }
    }

    private fun serviceBindingChecks(
        plan: SiteRemoteDeployPlan,
        trust: SiteRemotePreflightTrust,
        intent: SiteProductionServiceBindingIntent,
        observation: SiteProductionServiceBindingObservation,
        readinessMode: SiteProductionServiceBindingReadinessMode,
    ): List<SiteProductionServiceBindingCheck> {
        val configurationStatePassed = when (readinessMode) {
            SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED -> observation.configured
            SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION -> !observation.configured
        }
        val configurationStateDetail = when (readinessMode) {
            SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED ->
                "Exact production domain and port must already be configured before readiness approval"
            SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION ->
                "Exact production domain and port must still be unconfigured before post-coordinator activation"
        }
        return listOf(
            check(
                SiteProductionServiceBindingCheckCode.SERVER_HOST_IDENTITY,
                observation.remoteHostIdentity == plan.remoteHostIdentity,
                "Observed serving endpoint must belong to the exact deployment host",
            ),
            check(
                SiteProductionServiceBindingCheckCode.SERVER_KEY_FINGERPRINT,
                observation.serverKeySha256 == trust.expectedServerKeySha256,
                "Observed serving endpoint must come from the trusted server key",
            ),
            check(
                SiteProductionServiceBindingCheckCode.DOMAIN,
                observation.domain == intent.domain,
                "Observed serving domain must exactly match production intent",
            ),
            check(
                SiteProductionServiceBindingCheckCode.PORT,
                observation.port == intent.port,
                "Observed serving port must exactly match production intent",
            ),
            check(
                SiteProductionServiceBindingCheckCode.CONFIGURED,
                configurationStatePassed,
                configurationStateDetail,
            ),
        )
    }

    private fun check(
        code: SiteProductionServiceBindingCheckCode,
        passed: Boolean,
        detail: String,
    ) = SiteProductionServiceBindingCheck(code = code, passed = passed, detail = detail)

    private fun validateDraft(draft: SiteProductionDeploymentReadinessDraft) {
        require(draft.contractVersion == CONTRACT_VERSION) { "Unsupported production readiness contract version" }
        require(!draft.realServerMutationEnabled) { "Production readiness gate must never enable real-server mutation" }
        require(!draft.authorizesTransport) { "Production readiness gate must never authorize transport" }
        require(draft.requiresSeparateExecutionAuthorization) { "Production readiness must require a separate execution authorization" }
        SiteRemoteDeployPolicy.validatePlan(draft.deploymentPlan)
        SiteRemotePreflightPolicy.validateReport(draft.preflight)
        require(draft.exportManifest.planSha256 == draft.deploymentPlan.sourcePlanSha256) {
            "Readiness export manifest is bound to a different deployment plan"
        }
        require(draft.exportManifest.sourceTreeSha256 == draft.deploymentPlan.sourceTreeSha256) {
            "Readiness export tree is bound to a different deployment plan"
        }
        require(draft.preflight.deploymentPlanSha256 == draft.deploymentPlan.deploymentPlanSha256) {
            "Readiness preflight is bound to a different deployment plan"
        }
        require(sha256.matches(draft.serviceBindingObservationSha256)) { "Service-binding observation SHA-256 is invalid" }
        require(sha256.matches(draft.operatorApprovalChallengeSha256)) { "Operator challenge SHA-256 is invalid" }
        require(sha256.matches(draft.readinessSha256)) { "Production readiness SHA-256 is invalid" }
        val expectedStatus = if (draft.blockers.isEmpty() && draft.preflight.status == SiteRemotePreflightStatus.READY && draft.serviceBindingChecks.all { it.passed }) {
            SiteProductionDeploymentReadinessStatus.AWAITING_OPERATOR_APPROVAL
        } else {
            SiteProductionDeploymentReadinessStatus.BLOCKED
        }
        require(draft.status == expectedStatus) { "Production readiness status does not match evidence" }
        require(draft.readinessSha256 == readinessSha256(draft.copy(readinessSha256 = ""))) {
            "Production readiness SHA-256 mismatch"
        }
    }

    private fun validateReadyRecord(record: SiteProductionDeploymentReadyRecord) {
        require(record.contractVersion == CONTRACT_VERSION) { "Unsupported ready-record contract version" }
        require(record.status == SiteProductionDeploymentReadinessStatus.READY_FOR_EXPLICIT_EXECUTION) {
            "Ready record has invalid status"
        }
        require(record.operatorApproved) { "Ready record must contain explicit operator approval" }
        require(!record.realServerMutationEnabled) { "Ready record must not enable real-server mutation" }
        require(!record.authorizesTransport) { "Ready record must not authorize transport" }
        require(record.requiresSeparateExecutionAuthorization) { "Ready record must require separate execution authorization" }
        listOf(
            record.operatorApprovalChallengeSha256,
            record.readinessSha256,
            record.deploymentPlanSha256,
            record.preflightSha256,
            record.exportPlanSha256,
            record.sourceTreeSha256,
            record.serviceBindingObservationSha256,
            record.approvalRecordSha256,
        ).forEach { require(sha256.matches(it)) { "Ready record contains invalid SHA-256 evidence" } }
        require(record.remoteHostIdentity.isNotBlank()) { "Ready record remote host identity is blank" }
        SiteRemoteDeployPolicy.prepareTargetRoot(record.targetRoot)
        SiteRemoteDeployPolicy.prepareTargetRoot(record.stagingRoot)
        record.backupRoot?.let(SiteRemoteDeployPolicy::prepareTargetRoot)
        require(record.remoteObservationObservedAtEpochMillis <= record.evaluatedAtEpochMillis) { "Ready record remote observation is from the future" }
        require(record.serviceBindingObservedAtEpochMillis <= record.evaluatedAtEpochMillis) { "Ready record service observation is from the future" }
        require(record.maxObservationAgeMillis > 0L) { "Ready record max observation age is invalid" }
        require(record.evaluatedAtEpochMillis - record.remoteObservationObservedAtEpochMillis <= record.maxObservationAgeMillis) { "Ready record remote observation is stale" }
        require(record.evaluatedAtEpochMillis - record.serviceBindingObservedAtEpochMillis <= record.maxObservationAgeMillis) { "Ready record service observation is stale" }
        require(record.serviceBindingPort in 1..65535) { "Ready record service port is invalid" }
        require(record.serviceBindingDomain == SiteRemoteDeployPolicy.normalizeDomain(record.serviceBindingDomain)) {
            "Ready record service domain is not normalized"
        }
        require(record.approvalRecordSha256 == approvalRecordSha256(record.copy(approvalRecordSha256 = ""))) {
            "Ready record approval SHA-256 mismatch"
        }
    }

    private fun serviceBindingObservationSha256(observation: SiteProductionServiceBindingObservation): String {
        val canonical = buildString {
            append("remoteHostIdentity=").append(observation.remoteHostIdentity).append('\n')
            append("serverKeySha256=").append(observation.serverKeySha256).append('\n')
            append("domain=").append(observation.domain).append('\n')
            append("port=").append(observation.port).append('\n')
            append("configured=").append(observation.configured).append('\n')
            append("observedAtEpochMillis=").append(observation.observedAtEpochMillis).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun approvalChallengeSha256(
        exportManifest: SiteExportManifest,
        plan: SiteRemoteDeployPlan,
        preflight: SiteRemotePreflightReport,
        serviceBindingIntent: SiteProductionServiceBindingIntent,
        serviceBindingReadinessMode: SiteProductionServiceBindingReadinessMode,
        serviceBindingObservationSha256: String,
        remoteObservationObservedAtEpochMillis: Long,
        serviceBindingObservedAtEpochMillis: Long,
        freshnessPolicy: SiteProductionObservationFreshnessPolicy,
    ): String {
        val canonical = buildString {
            append("contractVersion=").append(CONTRACT_VERSION).append('\n')
            append("exportPlanSha256=").append(exportManifest.planSha256).append('\n')
            append("sourceTreeSha256=").append(exportManifest.sourceTreeSha256).append('\n')
            append("outputName=").append(exportManifest.outputName).append('\n')
            append("format=").append(exportManifest.format.name).append('\n')
            append("fileCount=").append(exportManifest.fileCount).append('\n')
            append("totalBytes=").append(exportManifest.totalBytes).append('\n')
            append("deploymentPlanSha256=").append(plan.deploymentPlanSha256).append('\n')
            append("remoteHostIdentity=").append(plan.remoteHostIdentity).append('\n')
            append("targetRoot=").append(plan.publish.targetRoot).append('\n')
            append("certificateMode=").append(plan.certificate.mode.name).append('\n')
            append("certificateDomain=").append(plan.certificate.requiredDomain ?: "").append('\n')
            append("preflightSha256=").append(preflight.preflightSha256).append('\n')
            append("observationSha256=").append(preflight.observationSha256).append('\n')
            append("remoteObservationObservedAtEpochMillis=").append(remoteObservationObservedAtEpochMillis).append('\n')
            append("serviceBindingObservedAtEpochMillis=").append(serviceBindingObservedAtEpochMillis).append('\n')
            append("evaluatedAtEpochMillis=").append(freshnessPolicy.evaluatedAtEpochMillis).append('\n')
            append("maxObservationAgeMillis=").append(freshnessPolicy.maxAgeMillis).append('\n')
            append("serviceDomain=").append(serviceBindingIntent.domain).append('\n')
            append("servicePort=").append(serviceBindingIntent.port).append('\n')
            append("serviceBindingReadinessMode=").append(serviceBindingReadinessMode.name).append('\n')
            append("serviceBindingObservationSha256=").append(serviceBindingObservationSha256).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun readinessSha256(draftWithoutSha: SiteProductionDeploymentReadinessDraft): String {
        val canonical = buildString {
            append("contractVersion=").append(draftWithoutSha.contractVersion).append('\n')
            append("status=").append(draftWithoutSha.status.name).append('\n')
            append("realServerMutationEnabled=").append(draftWithoutSha.realServerMutationEnabled).append('\n')
            append("authorizesTransport=").append(draftWithoutSha.authorizesTransport).append('\n')
            append("requiresSeparateExecutionAuthorization=").append(draftWithoutSha.requiresSeparateExecutionAuthorization).append('\n')
            append("exportPlanSha256=").append(draftWithoutSha.exportManifest.planSha256).append('\n')
            append("sourceTreeSha256=").append(draftWithoutSha.exportManifest.sourceTreeSha256).append('\n')
            append("deploymentPlanSha256=").append(draftWithoutSha.deploymentPlan.deploymentPlanSha256).append('\n')
            append("preflightSha256=").append(draftWithoutSha.preflight.preflightSha256).append('\n')
            append("remoteObservationObservedAtEpochMillis=").append(draftWithoutSha.remoteObservationObservedAtEpochMillis).append('\n')
            append("serviceBindingObservedAtEpochMillis=").append(draftWithoutSha.serviceBindingObservedAtEpochMillis).append('\n')
            append("evaluatedAtEpochMillis=").append(draftWithoutSha.freshnessPolicy.evaluatedAtEpochMillis).append('\n')
            append("maxObservationAgeMillis=").append(draftWithoutSha.freshnessPolicy.maxAgeMillis).append('\n')
            append("serviceDomain=").append(draftWithoutSha.serviceBindingIntent.domain).append('\n')
            append("servicePort=").append(draftWithoutSha.serviceBindingIntent.port).append('\n')
            append("serviceBindingReadinessMode=").append(draftWithoutSha.serviceBindingReadinessMode.name).append('\n')
            append("serviceBindingObservationSha256=").append(draftWithoutSha.serviceBindingObservationSha256).append('\n')
            append("operatorApprovalChallengeSha256=").append(draftWithoutSha.operatorApprovalChallengeSha256).append('\n')
            draftWithoutSha.serviceBindingChecks.forEach { check ->
                append("serviceCheck=").append(check.code.name).append('\u0000')
                append(check.passed).append('\u0000').append(check.detail).append('\n')
            }
            draftWithoutSha.blockers.forEach { blocker ->
                append("blocker=").append(blocker.scope).append('\u0000')
                append(blocker.code).append('\u0000').append(blocker.detail).append('\n')
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun approvalRecordSha256(recordWithoutSha: SiteProductionDeploymentReadyRecord): String {
        val canonical = buildString {
            append("contractVersion=").append(recordWithoutSha.contractVersion).append('\n')
            append("status=").append(recordWithoutSha.status.name).append('\n')
            append("operatorApproved=").append(recordWithoutSha.operatorApproved).append('\n')
            append("operatorApprovalChallengeSha256=").append(recordWithoutSha.operatorApprovalChallengeSha256).append('\n')
            append("readinessSha256=").append(recordWithoutSha.readinessSha256).append('\n')
            append("deploymentPlanSha256=").append(recordWithoutSha.deploymentPlanSha256).append('\n')
            append("preflightSha256=").append(recordWithoutSha.preflightSha256).append('\n')
            append("exportPlanSha256=").append(recordWithoutSha.exportPlanSha256).append('\n')
            append("sourceTreeSha256=").append(recordWithoutSha.sourceTreeSha256).append('\n')
            append("remoteHostIdentity=").append(recordWithoutSha.remoteHostIdentity).append('\n')
            append("targetRoot=").append(recordWithoutSha.targetRoot).append('\n')
            append("stagingRoot=").append(recordWithoutSha.stagingRoot).append('\n')
            append("backupRoot=").append(recordWithoutSha.backupRoot ?: "").append('\n')
            append("serviceBindingDomain=").append(recordWithoutSha.serviceBindingDomain).append('\n')
            append("serviceBindingPort=").append(recordWithoutSha.serviceBindingPort).append('\n')
            append("serviceBindingReadinessMode=").append(recordWithoutSha.serviceBindingReadinessMode.name).append('\n')
            append("serviceBindingObservationSha256=").append(recordWithoutSha.serviceBindingObservationSha256).append('\n')
            append("remoteObservationObservedAtEpochMillis=").append(recordWithoutSha.remoteObservationObservedAtEpochMillis).append('\n')
            append("serviceBindingObservedAtEpochMillis=").append(recordWithoutSha.serviceBindingObservedAtEpochMillis).append('\n')
            append("evaluatedAtEpochMillis=").append(recordWithoutSha.evaluatedAtEpochMillis).append('\n')
            append("maxObservationAgeMillis=").append(recordWithoutSha.maxObservationAgeMillis).append('\n')
            append("realServerMutationEnabled=").append(recordWithoutSha.realServerMutationEnabled).append('\n')
            append("authorizesTransport=").append(recordWithoutSha.authorizesTransport).append('\n')
            append("requiresSeparateExecutionAuthorization=").append(recordWithoutSha.requiresSeparateExecutionAuthorization).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }
}

package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingReadinessMode
import java.security.MessageDigest

/**
 * Phase 11.96 release bootstrap gate, upgraded by Phase 11.98 for explicit HTTPS reuse.
 *
 * Action: a caller deliberately selects a release flow and presents one already-reviewed exact
 * production execution context.
 * Consequence: only an honest first-publication context with fresh unconfigured endpoint evidence
 * and complete post-coordinator serving capability can be admitted for publication to the real UI
 * port. Explicit certificate reuse is admitted only with the Phase 11.98 no-downgrade HTTPS/TLS
 * completion requirement.
 * Counteraction: every legacy/mismatched/stale-shaped or incomplete serving context fails closed
 * before it can enter the process-local production context registry.
 */
internal object SiteProductionDeploymentAndroidReleaseBootstrapBoundary {
    const val CONTRACT_VERSION: Int = 2

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun readinessModeFor(
        releaseFlow: SiteProductionDeploymentReleaseFlow,
    ): SiteProductionServiceBindingReadinessMode = when (releaseFlow) {
        SiteProductionDeploymentReleaseFlow.PRECONFIGURED_ENDPOINT ->
            SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED
        SiteProductionDeploymentReleaseFlow.FIRST_PUBLICATION_POST_COORDINATOR ->
            SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION
    }

    fun evidenceFrom(
        releaseFlow: SiteProductionDeploymentReleaseFlow,
        context: SiteProductionDeploymentAndroidProductionExecutionContext,
    ): SiteProductionDeploymentReleaseBootstrapEvidence {
        SiteProductionDeploymentAndroidProductionExecutionContextRegistry.validateContext(context)
        val executionRequest = context.runtimeMutationRequest.executionRequest
        val readinessRequest = executionRequest.readinessRequest
        val readyRecord = executionRequest.readyRecord
        val preparation = context.preparation
        val pinnedHostKeySha256 = when (
            val parsed = CanonicalHostKeyFingerprint.parse(context.serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }

        return SiteProductionDeploymentReleaseBootstrapEvidence(
            releaseFlow = releaseFlow,
            serverAccessId = context.serverAccess.id.value,
            serverId = context.serverAccess.serverId.value,
            remoteHostIdentity = context.serverAccess.endpoint.host,
            sshPort = context.serverAccess.endpoint.port,
            sshUsername = context.serverAccess.username,
            serverAccessPinnedHostKeySha256 = pinnedHostKeySha256,
            expectedServerKeySha256 = readinessRequest.trust.expectedServerKeySha256,
            remoteObservationHostIdentity = readinessRequest.remoteObservation.server.remoteHostIdentity,
            remoteObservationServerKeySha256 = readinessRequest.remoteObservation.server.serverKeySha256,
            serviceObservationHostIdentity = readinessRequest.serviceBindingObservation.remoteHostIdentity,
            serviceObservationServerKeySha256 = readinessRequest.serviceBindingObservation.serverKeySha256,
            serviceDomain = readinessRequest.serviceBindingIntent.domain,
            servicePort = readinessRequest.serviceBindingIntent.port,
            serviceBindingReadinessMode = readinessRequest.serviceBindingReadinessMode,
            serviceBindingObservedConfigured = readinessRequest.serviceBindingObservation.configured,
            readyRecordServiceBindingReadinessMode = readyRecord.serviceBindingReadinessMode,
            readyRecordOperatorApproved = readyRecord.operatorApproved,
            readyRecordApprovalSha256 = readyRecord.approvalRecordSha256,
            preparationSha256 = preparation.preparationSha256,
            deploymentPlanSha256 = preparation.remoteDeployPlan.deploymentPlanSha256,
            sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            coordinatorAdmissionSha256 = context.coordinatorAdmission.admissionSha256,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            certificateReuseMode = preparation.remoteDeployPlan.certificate.mode,
            postCoordinatorCredentialProviderPresent = context.postCoordinatorCredentialProvider != null,
            uiPreparedAtEpochMillis = context.uiPreparedAtEpochMillis,
            permitExpiresAtEpochMillis = context.coordinatorAdmission.permitExpiresAtEpochMillis,
        )
    }

    fun admitReviewedFirstPublication(
        evidence: SiteProductionDeploymentReleaseBootstrapEvidence,
    ): SiteProductionDeploymentReleaseBootstrapAdmission {
        require(evidence.releaseFlow == SiteProductionDeploymentReleaseFlow.FIRST_PUBLICATION_POST_COORDINATOR) {
            "Release bootstrap admission is restricted to the reviewed first-publication flow"
        }
        val selectedMode = readinessModeFor(evidence.releaseFlow)
        require(selectedMode == SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION)
        require(evidence.serviceBindingReadinessMode == selectedMode) {
            "First-publication readiness was not bound to post-coordinator activation"
        }
        require(evidence.readyRecordServiceBindingReadinessMode == selectedMode) {
            "Approved ready record was produced for a different service-binding readiness mode"
        }
        require(!evidence.serviceBindingObservedConfigured) {
            "First-publication bootstrap requires fresh evidence that the exact endpoint is not configured yet"
        }
        require(evidence.readyRecordOperatorApproved) {
            "First-publication bootstrap requires an explicitly operator-approved ready record"
        }
        require(evidence.postCoordinatorCredentialProviderPresent) {
            "First-publication bootstrap requires complete post-coordinator serving capability"
        }
        val requiresFinalHttpsTlsVerification = when (evidence.certificateReuseMode) {
            SiteCertificateReuseMode.NONE -> false
            SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN -> true
        }
        requireCommonEvidence(evidence)

        val base = SiteProductionDeploymentReleaseBootstrapAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentReleaseBootstrapStatus
                .READY_TO_PUBLISH_REVIEWED_FIRST_PUBLICATION_CONTEXT,
            releaseFlow = evidence.releaseFlow,
            selectedReadinessMode = selectedMode,
            serverAccessId = evidence.serverAccessId,
            remoteHostIdentity = evidence.remoteHostIdentity,
            serviceDomain = evidence.serviceDomain,
            servicePort = evidence.servicePort,
            targetRoot = evidence.targetRoot,
            preparationSha256 = evidence.preparationSha256,
            deploymentPlanSha256 = evidence.deploymentPlanSha256,
            sourceTreeSha256 = evidence.sourceTreeSha256,
            coordinatorAdmissionSha256 = evidence.coordinatorAdmissionSha256,
            readyRecordApprovalSha256 = evidence.readyRecordApprovalSha256,
            certificateReuseMode = evidence.certificateReuseMode,
            completePostCoordinatorServingCapabilityRequired = true,
            requiresFinalHttpsTlsVerification = requiresFinalHttpsTlsVerification,
            productionNetworkTouched = false,
            credentialMaterialRead = false,
            realServerMutationEnabled = false,
            authorizesTransport = false,
            authorizesCoordinatorInvocation = false,
            automaticRetryAuthorized = false,
            arbitraryCommandAuthorized = false,
            silentProtocolDowngradePerformed = false,
            bootstrapAdmissionSha256 = "",
        )
        return base.copy(bootstrapAdmissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    /**
     * Replacement of an existing site whose exact VELUM nginx endpoint is already configured.
     *
     * Action: the operator explicitly chose "replace existing site" after the read-only probe found
     * the previous site in the same folder and the deterministic nginx config already serving it.
     * Consequence: only the static tree is swapped by the rename-only replacement transaction; the
     * previous tree is restored automatically if the commit cannot be verified.
     * Counteraction: a context without fresh "already configured" evidence, with post-coordinator
     * nginx activation, or with certificate reuse fails closed.
     */
    fun admitReviewedReplacement(
        evidence: SiteProductionDeploymentReleaseBootstrapEvidence,
        replacementPolicyBound: Boolean,
        previousTargetTreeBound: Boolean,
    ): SiteProductionDeploymentReleaseBootstrapAdmission {
        require(evidence.releaseFlow == SiteProductionDeploymentReleaseFlow.PRECONFIGURED_ENDPOINT) {
            "Replacement admission requires the preconfigured-endpoint flow"
        }
        val selectedMode = readinessModeFor(evidence.releaseFlow)
        require(evidence.serviceBindingReadinessMode == selectedMode) {
            "Replacement readiness was not bound to an already configured endpoint"
        }
        require(evidence.readyRecordServiceBindingReadinessMode == selectedMode) {
            "Approved ready record was produced for a different service-binding readiness mode"
        }
        require(evidence.serviceBindingObservedConfigured) {
            "Replacement requires fresh evidence that the exact endpoint is already configured"
        }
        require(evidence.readyRecordOperatorApproved) {
            "Replacement requires an explicitly operator-approved ready record"
        }
        require(!evidence.postCoordinatorCredentialProviderPresent) {
            "Replacement of an already served site must not activate or reload nginx"
        }
        require(evidence.certificateReuseMode == SiteCertificateReuseMode.NONE) {
            "Replacement of an already served site does not change certificates"
        }
        require(replacementPolicyBound) { "Replacement requires the backup-and-replace target policy" }
        require(previousTargetTreeBound) { "Replacement requires the exact observed previous site tree" }
        requireCommonEvidence(evidence)

        val base = SiteProductionDeploymentReleaseBootstrapAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentReleaseBootstrapStatus.READY_TO_PUBLISH_REVIEWED_REPLACEMENT_CONTEXT,
            releaseFlow = evidence.releaseFlow,
            selectedReadinessMode = selectedMode,
            serverAccessId = evidence.serverAccessId,
            remoteHostIdentity = evidence.remoteHostIdentity,
            serviceDomain = evidence.serviceDomain,
            servicePort = evidence.servicePort,
            targetRoot = evidence.targetRoot,
            preparationSha256 = evidence.preparationSha256,
            deploymentPlanSha256 = evidence.deploymentPlanSha256,
            sourceTreeSha256 = evidence.sourceTreeSha256,
            coordinatorAdmissionSha256 = evidence.coordinatorAdmissionSha256,
            readyRecordApprovalSha256 = evidence.readyRecordApprovalSha256,
            certificateReuseMode = evidence.certificateReuseMode,
            completePostCoordinatorServingCapabilityRequired = false,
            requiresFinalHttpsTlsVerification = false,
            productionNetworkTouched = false,
            credentialMaterialRead = false,
            realServerMutationEnabled = false,
            authorizesTransport = false,
            authorizesCoordinatorInvocation = false,
            automaticRetryAuthorized = false,
            arbitraryCommandAuthorized = false,
            silentProtocolDowngradePerformed = false,
            bootstrapAdmissionSha256 = "",
        )
        return base.copy(bootstrapAdmissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    private fun requireCommonEvidence(evidence: SiteProductionDeploymentReleaseBootstrapEvidence) {
        require(evidence.serverAccessId.isNotBlank())
        require(evidence.serverId.isNotBlank())
        require(evidence.remoteHostIdentity.isNotBlank() && evidence.remoteHostIdentity == evidence.remoteHostIdentity.trim())
        require(evidence.sshPort in 1..65535)
        require(evidence.sshUsername.isNotBlank() && evidence.sshUsername == evidence.sshUsername.trim())
        require(
            evidence.remoteObservationHostIdentity == evidence.remoteHostIdentity &&
                evidence.serviceObservationHostIdentity == evidence.remoteHostIdentity,
        ) { "Release bootstrap host identity differs across ServerAccess/read-only observations" }
        require(
            evidence.serverAccessPinnedHostKeySha256 == evidence.expectedServerKeySha256 &&
                evidence.remoteObservationServerKeySha256 == evidence.expectedServerKeySha256 &&
                evidence.serviceObservationServerKeySha256 == evidence.expectedServerKeySha256,
        ) { "Release bootstrap pinned host-key evidence differs across reviewed inputs" }
        require(evidence.serviceDomain.isNotBlank())
        require(evidence.servicePort in 1..65535)
        require(evidence.targetRoot.isNotBlank())
        require(evidence.uiPreparedAtEpochMillis <= evidence.permitExpiresAtEpochMillis) {
            "Release bootstrap context was prepared after its coordinator permit expired"
        }
        listOf(
            evidence.serverAccessPinnedHostKeySha256,
            evidence.expectedServerKeySha256,
            evidence.remoteObservationServerKeySha256,
            evidence.serviceObservationServerKeySha256,
            evidence.readyRecordApprovalSha256,
            evidence.preparationSha256,
            evidence.deploymentPlanSha256,
            evidence.sourceTreeSha256,
            evidence.coordinatorAdmissionSha256,
        ).forEach { require(sha256Pattern.matches(it)) { "Release bootstrap contains invalid SHA-256 evidence" } }
    }

    fun validateAdmission(admission: SiteProductionDeploymentReleaseBootstrapAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        when (admission.status) {
            SiteProductionDeploymentReleaseBootstrapStatus.READY_TO_PUBLISH_REVIEWED_FIRST_PUBLICATION_CONTEXT -> {
                require(admission.releaseFlow == SiteProductionDeploymentReleaseFlow.FIRST_PUBLICATION_POST_COORDINATOR)
                require(
                    admission.selectedReadinessMode ==
                        SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
                )
                require(admission.completePostCoordinatorServingCapabilityRequired)
                require(
                    admission.requiresFinalHttpsTlsVerification ==
                        (admission.certificateReuseMode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN),
                )
            }
            SiteProductionDeploymentReleaseBootstrapStatus.READY_TO_PUBLISH_REVIEWED_REPLACEMENT_CONTEXT -> {
                require(admission.releaseFlow == SiteProductionDeploymentReleaseFlow.PRECONFIGURED_ENDPOINT)
                require(
                    admission.selectedReadinessMode ==
                        SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED,
                )
                require(!admission.completePostCoordinatorServingCapabilityRequired)
                require(!admission.requiresFinalHttpsTlsVerification)
                require(admission.certificateReuseMode == SiteCertificateReuseMode.NONE)
            }
        }
        require(admission.serverAccessId.isNotBlank())
        require(admission.remoteHostIdentity.isNotBlank())
        require(admission.serviceDomain.isNotBlank())
        require(admission.servicePort in 1..65535)
        require(admission.targetRoot.isNotBlank())
        require(!admission.productionNetworkTouched)
        require(!admission.credentialMaterialRead)
        require(!admission.realServerMutationEnabled)
        require(!admission.authorizesTransport)
        require(!admission.authorizesCoordinatorInvocation)
        require(!admission.automaticRetryAuthorized)
        require(!admission.arbitraryCommandAuthorized)
        require(!admission.silentProtocolDowngradePerformed)
        listOf(
            admission.preparationSha256,
            admission.deploymentPlanSha256,
            admission.sourceTreeSha256,
            admission.coordinatorAdmissionSha256,
            admission.readyRecordApprovalSha256,
            admission.bootstrapAdmissionSha256,
        ).forEach { require(sha256Pattern.matches(it)) }
        require(
            admission.bootstrapAdmissionSha256 == admissionSha256(
                admission.copy(bootstrapAdmissionSha256 = ""),
            ),
        ) { "Release bootstrap admission SHA-256 mismatch" }
    }

    internal fun admissionSha256ForTest(
        admissionWithoutSha: SiteProductionDeploymentReleaseBootstrapAdmission,
    ): String = admissionSha256(admissionWithoutSha.copy(bootstrapAdmissionSha256 = ""))

    private fun admissionSha256(
        admissionWithoutSha: SiteProductionDeploymentReleaseBootstrapAdmission,
    ): String = sha256(
        buildString {
            append("phase=11.98-release-bootstrap-upgrade\n")
            append("contractVersion=").append(admissionWithoutSha.contractVersion).append('\n')
            append("status=").append(admissionWithoutSha.status.name).append('\n')
            append("releaseFlow=").append(admissionWithoutSha.releaseFlow.name).append('\n')
            append("selectedReadinessMode=").append(admissionWithoutSha.selectedReadinessMode.name).append('\n')
            append("serverAccessId=").append(admissionWithoutSha.serverAccessId).append('\n')
            append("remoteHostIdentity=").append(admissionWithoutSha.remoteHostIdentity).append('\n')
            append("serviceDomain=").append(admissionWithoutSha.serviceDomain).append('\n')
            append("servicePort=").append(admissionWithoutSha.servicePort).append('\n')
            append("targetRoot=").append(admissionWithoutSha.targetRoot).append('\n')
            append("preparationSha256=").append(admissionWithoutSha.preparationSha256).append('\n')
            append("deploymentPlanSha256=").append(admissionWithoutSha.deploymentPlanSha256).append('\n')
            append("sourceTreeSha256=").append(admissionWithoutSha.sourceTreeSha256).append('\n')
            append("coordinatorAdmissionSha256=").append(admissionWithoutSha.coordinatorAdmissionSha256).append('\n')
            append("readyRecordApprovalSha256=").append(admissionWithoutSha.readyRecordApprovalSha256).append('\n')
            append("certificateReuseMode=").append(admissionWithoutSha.certificateReuseMode.name).append('\n')
            append("completePostCoordinatorServingCapabilityRequired=")
                .append(admissionWithoutSha.completePostCoordinatorServingCapabilityRequired).append('\n')
            append("requiresFinalHttpsTlsVerification=")
                .append(admissionWithoutSha.requiresFinalHttpsTlsVerification).append('\n')
            append("productionNetworkTouched=").append(admissionWithoutSha.productionNetworkTouched).append('\n')
            append("credentialMaterialRead=").append(admissionWithoutSha.credentialMaterialRead).append('\n')
            append("realServerMutationEnabled=").append(admissionWithoutSha.realServerMutationEnabled).append('\n')
            append("authorizesTransport=").append(admissionWithoutSha.authorizesTransport).append('\n')
            append("authorizesCoordinatorInvocation=").append(admissionWithoutSha.authorizesCoordinatorInvocation).append('\n')
            append("automaticRetryAuthorized=").append(admissionWithoutSha.automaticRetryAuthorized).append('\n')
            append("arbitraryCommandAuthorized=").append(admissionWithoutSha.arbitraryCommandAuthorized).append('\n')
            append("silentProtocolDowngradePerformed=")
                .append(admissionWithoutSha.silentProtocolDowngradePerformed).append('\n')
        },
    )

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

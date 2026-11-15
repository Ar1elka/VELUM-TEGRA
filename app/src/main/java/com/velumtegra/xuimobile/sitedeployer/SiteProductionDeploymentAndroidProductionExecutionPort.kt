package com.velumtegra.xuimobile.sitedeployer

import android.util.Log
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteDeployerRemoteTreeExpectation
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteDeployerReviewState
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentCoordinatorInvocationAuthorization
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationRequest
import com.velumtegra.xuimobile.core.site.SiteCaddyServingPlan
import com.velumtegra.xuimobile.core.site.SiteServingBackend
import com.velumtegra.xuimobile.core.site.SiteServingFailureCategory
import com.velumtegra.xuimobile.core.site.SiteServingOutcome
import com.velumtegra.xuimobile.core.ssh.SiteCaddyCommandFailedException
import com.velumtegra.xuimobile.core.ssh.SiteExternalReachabilityProbe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Exact already-authorized Phase 11.80 input bundle that may be surfaced to the UI by Phase 11.82.
 * It contains references to the accepted runtime objects, never raw credential material.
 */
internal data class SiteProductionDeploymentAndroidProductionExecutionContext(
    val preparation: SiteDeployerLocalPreparationResult,
    val coordinatorAdmission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
    val invocationAuthorization: SiteProductionDeploymentCoordinatorInvocationAuthorization,
    val runtimeMutationRequest: SiteProductionDeploymentRuntimeMutationRequest,
    val serverAccess: ServerAccess,
    val credentialProvider: SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider,
    val postCoordinatorCredentialProvider:
        SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider? = null,
    val previousTargetTree: SiteDeployerRemoteTreeExpectation? = null,
    val uiPreparedAtEpochMillis: Long,
    /** Reviewed Caddy serving plan; when present Caddy (not nginx) serves the committed tree. */
    val caddyServingPlan: SiteCaddyServingPlan? = null,
    /**
     * Files-only replacement of a site nginx already serves: the address to verify from the device.
     * The kept config decides the scheme, not the (disabled) certificate-reuse planning.
     */
    val replacementVerificationUrl: String? = null,
)

/**
 * Process-local handoff for one reviewed production execution context. Publishing a context does not
 * execute network I/O and does not authorize the UI by itself. The Phase 11.81 three-confirmation
 * UI boundary and the Phase 11.80 durable replay fence remain mandatory.
 */
internal class SiteProductionDeploymentAndroidProductionExecutionContextRegistry {
    @Volatile
    private var active: SiteProductionDeploymentAndroidProductionExecutionContext? = null

    @Synchronized
    fun installOnce(context: SiteProductionDeploymentAndroidProductionExecutionContext): Boolean {
        validateContext(context)
        if (active != null) return false
        active = context
        return true
    }

    @Synchronized
    fun clear() {
        active = null
    }

    fun currentTargetBinding(): SiteProductionDeploymentUiTargetBinding? {
        val context = active ?: return null
        validateContext(context)
        val plan = context.preparation.remoteDeployPlan
        return SiteProductionDeploymentUiTargetBinding(
            remoteHostIdentity = plan.remoteHostIdentity,
            targetRoot = plan.publish.targetRoot,
            owner = plan.publish.owner,
            group = plan.publish.group,
            existingTargetPolicy = plan.publish.existingTargetPolicy,
            certificateReuseRequested = plan.certificate.mode ==
                SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
            trustedServerKeySha256 = context.runtimeMutationRequest.executionRequest
                .readinessRequest.trust.expectedServerKeySha256,
        )
    }

    fun currentForReview(review: SiteDeployerReviewState): SiteProductionDeploymentAndroidProductionExecutionContext? {
        val context = active ?: return null
        val plan = context.preparation.remoteDeployPlan
        val certificateReuseRequested = plan.certificate.mode ==
            SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN
        return context.takeIf {
            review.preview.treeSha256 == it.preparation.previewExport.preview.treeSha256 &&
                review.exportManifest.planSha256 == it.preparation.previewExport.export.manifest.planSha256 &&
                review.serviceBinding.domain == it.preparation.serviceBinding.domain &&
                review.serviceBinding.port == it.preparation.serviceBinding.port &&
                review.remoteTarget.remoteHostIdentity == plan.remoteHostIdentity &&
                review.remoteTarget.targetRoot == plan.publish.targetRoot &&
                review.remoteTarget.existingTargetPolicy == plan.publish.existingTargetPolicy &&
                review.certificate.requested == certificateReuseRequested
        }
    }

    @Synchronized
    fun consumeForAuthorization(
        authorization: SiteProductionDeploymentUiExecutionAuthorization,
    ): SiteProductionDeploymentAndroidProductionExecutionContext? {
        val context = active ?: return null
        val matches = authorization.phase1180AdmissionSha256 == context.coordinatorAdmission.admissionSha256 &&
            authorization.sourceTreeSha256 == context.preparation.remoteDeployPlan.sourceTreeSha256 &&
            authorization.deploymentPlanSha256 == context.preparation.remoteDeployPlan.deploymentPlanSha256 &&
            authorization.remoteHostIdentity == context.serverAccess.endpoint.host &&
            authorization.targetRoot == context.preparation.remoteDeployPlan.publish.targetRoot &&
            authorization.serviceDomain == context.preparation.serviceBinding.domain &&
            authorization.servicePort == context.preparation.serviceBinding.port &&
            authorization.phase1180CoordinatorInvocationId == context.coordinatorAdmission.coordinatorInvocationId
        if (!matches) return null
        active = null
        return context
    }

    companion object {
        fun validateContext(context: SiteProductionDeploymentAndroidProductionExecutionContext) {
            SiteDeployerLocalPreparationBoundary.validate(context.preparation)
            SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
                .validateAdmission(context.coordinatorAdmission)
            require(context.coordinatorAdmission.invocationAuthorizationSha256 ==
                context.invocationAuthorization.invocationAuthorizationSha256)
            require(context.coordinatorAdmission.executionAuthorizationSha256 ==
                context.runtimeMutationRequest.executionAuthorization.executionAuthorizationSha256)
            require(context.coordinatorAdmission.localPreparationSha256 == context.preparation.preparationSha256)
            require(context.coordinatorAdmission.deploymentPlanSha256 ==
                context.preparation.remoteDeployPlan.deploymentPlanSha256)
            require(context.coordinatorAdmission.sourceTreeSha256 == context.preparation.remoteDeployPlan.sourceTreeSha256)
            require(context.coordinatorAdmission.remoteHostIdentity == context.serverAccess.endpoint.host)
            require(context.coordinatorAdmission.targetRoot == context.preparation.remoteDeployPlan.publish.targetRoot)
            require(context.coordinatorAdmission.coordinatorInvocationId ==
                context.invocationAuthorization.coordinatorInvocationId)
            val rebuilt = SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary.admit(
                invocationAuthorization = context.invocationAuthorization,
                runtimeMutationRequest = context.runtimeMutationRequest,
                preparation = context.preparation,
                serverAccess = context.serverAccess,
                evaluatedAtEpochMillis = context.coordinatorAdmission.evaluatedAtEpochMillis,
            )
            require(rebuilt == context.coordinatorAdmission) {
                "Production execution context no longer matches exact Phase 11.80 admission inputs"
            }
            require(context.uiPreparedAtEpochMillis >= context.coordinatorAdmission.evaluatedAtEpochMillis)
            require(context.uiPreparedAtEpochMillis <= context.coordinatorAdmission.permitExpiresAtEpochMillis)
        }
    }
}

/**
 * Phase 11.82/11.94/11.98 concrete production port. It remains the only Android UI -> Phase 11.80
 * adapter. A complete reviewed context continues one successful exact-static-tree commit through the
 * accepted HTTP chain when certificate reuse is NONE, or through the exact existing-certificate
 * HTTPS/TLS chain when reuse was explicitly requested and proven. Legacy contexts without a
 * post-coordinator provider preserve the Phase 11.82 static-only regression behavior.
 */
internal class SiteProductionDeploymentAndroidProductionExecutionPort(
    private val contextRegistry: SiteProductionDeploymentAndroidProductionExecutionContextRegistry,
    private val replayFence: SiteProductionDeploymentDurableReplayFence,
    private val nowEpochMillis: () -> Long = System::currentTimeMillis,
    private val externalProbe: SiteExternalReachabilityProbe = SiteExternalReachabilityProbe(),
) : SiteDeployerProductionExecutionPort {
    private data class UiBinding(
        val context: SiteProductionDeploymentAndroidProductionExecutionContext,
        val admission: SiteProductionDeploymentUiAdmission,
    )

    @Volatile
    private var binding: UiBinding? = null

    override fun currentTargetBinding(): SiteProductionDeploymentUiTargetBinding? =
        contextRegistry.currentTargetBinding()

    override fun currentAdmission(review: SiteDeployerReviewState): SiteProductionDeploymentUiAdmission? {
        val context = contextRegistry.currentForReview(review) ?: run {
            binding = null
            return null
        }
        SiteProductionDeploymentAndroidProductionExecutionContextRegistry.validateContext(context)
        val admission = SiteProductionDeploymentAndroidUiExecutionBoundary.prepare(
            review = review,
            preparation = context.preparation,
            coordinatorAdmission = context.coordinatorAdmission,
            preparedAtEpochMillis = context.uiPreparedAtEpochMillis,
        )
        binding = UiBinding(context, admission)
        return admission
    }

    override suspend fun executeOnce(
        authorization: SiteProductionDeploymentUiExecutionAuthorization,
    ): SiteProductionDeploymentUiExecutionReceipt {
        val exactBinding = binding ?: error("Production UI admission is no longer active")
        require(exactBinding.admission.admissionSha256 == authorization.uiAdmissionSha256) {
            "Production UI authorization is stale or bound to a different admission"
        }
        val executedAt = nowEpochMillis()
        SiteProductionDeploymentAndroidUiExecutionBoundary.validateForExecution(
            authorization = authorization,
            admission = exactBinding.admission,
            invokedAtEpochMillis = executedAt,
        )

        // Counteraction before action: consume the exact process-local handoff before any suspend
        // coordinator work. A second UI attempt has no app-level execution context even before the
        // authoritative Phase 11.80 durable coordinator fence is consulted.
        val currentContext = contextRegistry.consumeForAuthorization(authorization)
            ?: error("Production execution context changed, expired, or was already consumed")
        require(currentContext === exactBinding.context) {
            "Production execution context instance changed after UI approval"
        }
        binding = null
        SiteProductionDeploymentAndroidProductionExecutionContextRegistry.validateContext(currentContext)

        val result = try {
            // The UI calls this port from viewModelScope/Main. The accepted production coordinator
            // contains bounded blocking SSH/SFTP operations, so the entire single coordinator
            // invocation must leave the Android main thread. This changes only execution context:
            // admission, one-shot consumption, durable replay fencing and no-retry semantics stay exact.
            withContext(Dispatchers.IO) {
                SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary.executeOnce(
                    admission = currentContext.coordinatorAdmission,
                    invocationAuthorization = currentContext.invocationAuthorization,
                    runtimeMutationRequest = currentContext.runtimeMutationRequest,
                    preparation = currentContext.preparation,
                    serverAccess = currentContext.serverAccess,
                    previousTargetTree = currentContext.previousTargetTree,
                    credentialProvider = currentContext.credentialProvider,
                    replayFence = replayFence,
                    executedAtEpochMillis = executedAt,
                )
            }
        } catch (error: Throwable) {
            // Diagnostics only: preserve the exact fail-closed semantics and rethrow the same error.
            // No retry or cleanup is attempted here.
            Log.e(
                "Phase11_82Exec",
                "Coordinator execution failed after UI attempt consumption: ${error::class.java.name}: ${error.message}",
                error,
            )
            throw error
        }
        SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary.validateExecutionResult(
            result,
            currentContext.coordinatorAdmission,
            currentContext.preparation,
        )

        var phase1192Execution: SiteProductionDeploymentPostCoordinatorServingPathVerificationResult? = null
        var phase1198HttpsServingReceipt: SiteProductionDeploymentPostCoordinatorHttpsServingReceipt? = null
        var servingOutcome: SiteServingOutcome? = null
        val caddyPlan = currentContext.caddyServingPlan
        val plannedUrl = caddyPlan?.plannedUrl ?: currentContext.replacementVerificationUrl
            ?: plannedNginxUrl(currentContext.preparation)
        val indexSha256 = currentContext.preparation.bundle.documents.single { it.path == "index.html" }.sha256
        when (result.status) {
            SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                .COORDINATOR_COMMITTED_EXACT_STATIC_TREE -> {
                val provider = currentContext.postCoordinatorCredentialProvider
                when {
                    caddyPlan != null -> {
                        servingOutcome = try {
                            withContext(Dispatchers.IO) {
                                SiteProductionDeploymentAndroidCaddyServingOrchestrator.executeOnce(
                                    plan = caddyPlan,
                                    serverAccess = currentContext.serverAccess,
                                    credentialProvider = requireNotNull(provider) {
                                        "Caddy serving requires fresh post-coordinator credentials"
                                    },
                                    externalProbe = externalProbe,
                                )
                            }
                        } catch (error: Throwable) {
                            Log.e("SiteCaddyExec", "Caddy serving failed after exact static commit; no retry: ${error.message}")
                            notVerified(
                                SiteServingBackend.CADDY,
                                plannedUrl,
                                if (error is SiteCaddyCommandFailedException) {
                                    SiteServingFailureCategory.SERVER_COMMAND_FAILED
                                } else {
                                    SiteServingFailureCategory.SERVING_VERIFICATION
                                },
                                "Файлы загружены, публикация в Caddy прервалась. " +
                                    (error.message ?: error::class.java.simpleName),
                            )
                        }
                    }

                    provider != null -> {
                        try {
                            when (currentContext.preparation.remoteDeployPlan.certificate.mode) {
                                SiteCertificateReuseMode.NONE -> phase1192Execution = withContext(Dispatchers.IO) {
                                    SiteProductionDeploymentAndroidPostCoordinatorHttpServingOrchestrator.executeOnce(
                                        preparation = currentContext.preparation,
                                        coordinatorAdmission = currentContext.coordinatorAdmission,
                                        coordinatorExecution = result,
                                        serverAccess = currentContext.serverAccess,
                                        credentialProvider = provider,
                                        replayFence = replayFence,
                                    )
                                }

                                SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN ->
                                    phase1198HttpsServingReceipt = withContext(Dispatchers.IO) {
                                        SiteProductionDeploymentAndroidPostCoordinatorHttpsServingOrchestrator.executeOnce(
                                            preparation = currentContext.preparation,
                                            coordinatorAdmission = currentContext.coordinatorAdmission,
                                            coordinatorExecution = result,
                                            serverAccess = currentContext.serverAccess,
                                            credentialProvider = provider,
                                            replayFence = replayFence,
                                        )
                                    }
                            }
                        } catch (error: Throwable) {
                            // The exact static tree is committed, but nginx serving did not complete.
                            // Report it honestly instead of a generic error; no retry is attempted.
                            Log.e("Phase11_94Exec", "Post-coordinator nginx serving failed after exact static commit", error)
                            phase1192Execution = null
                            phase1198HttpsServingReceipt = null
                            servingOutcome = notVerified(
                                SiteServingBackend.NGINX,
                                plannedUrl,
                                categoryOf(error),
                                "Nginx не начал обслуживать сайт: ${error.message ?: error::class.java.simpleName}",
                            )
                        }
                        if (servingOutcome == null) {
                            servingOutcome = verifyFromDevice(SiteServingBackend.NGINX, plannedUrl, indexSha256)
                        }
                    }

                    // Static-only replacement of a site the web server already serves.
                    else -> servingOutcome = verifyFromDevice(null, plannedUrl, indexSha256)
                }
            }

            SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                .COORDINATOR_ROLLED_BACK_CLEAN -> Unit
        }
        val notReachable = servingOutcome?.externallyReachable == false
        if (notReachable) {
            phase1192Execution = null
            phase1198HttpsServingReceipt = null
        }
        val uiStatus = when {
            result.status == SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                .COORDINATOR_ROLLED_BACK_CLEAN ->
                SiteProductionDeploymentUiExecutionStatus.COORDINATOR_ROLLED_BACK_CLEAN
            notReachable -> SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_SERVING_NOT_VERIFIED
            caddyPlan != null -> SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_AND_CADDY_SERVING_VERIFIED
            phase1198HttpsServingReceipt != null ->
                SiteProductionDeploymentUiExecutionStatus
                    .COORDINATOR_COMMITTED_AND_HTTPS_TLS_SERVING_PATH_VERIFIED
            phase1192Execution != null ->
                SiteProductionDeploymentUiExecutionStatus
                    .COORDINATOR_COMMITTED_AND_HTTP_SERVING_PATH_VERIFIED
            else -> SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_EXACT_STATIC_TREE
        }
        return SiteProductionDeploymentAndroidUiExecutionBoundary.complete(
            authorization = authorization,
            status = uiStatus,
            phase1180ExecutionResultSha256 = result.executionResultSha256,
            completedAtEpochMillis = nowEpochMillis().coerceAtLeast(executedAt),
            phase1192ExecutionResultSha256 = phase1192Execution?.executionResultSha256,
            completeHttpServingPathVerified = phase1192Execution != null,
            phase1198HttpsServingReceiptSha256 = phase1198HttpsServingReceipt?.receiptSha256,
            phase1197ExecutionResultSha256 = phase1198HttpsServingReceipt?.phase1197ExecutionResultSha256,
            completeHttpsTlsServingPathVerified = phase1198HttpsServingReceipt != null,
            servingOutcome = servingOutcome,
        )
    }

    private suspend fun verifyFromDevice(
        backend: SiteServingBackend?,
        plannedUrl: String,
        indexSha256: String,
    ): SiteServingOutcome {
        val fetched = withContext(Dispatchers.IO) { externalProbe.fetch(plannedUrl + "index.html", indexSha256) }
        return if (fetched.reachable) {
            SiteServingOutcome(backend, plannedUrl, plannedUrl, true, true, false, null, null)
        } else {
            SiteServingOutcome(
                backend = backend,
                plannedUrl = plannedUrl,
                verifiedUrl = null,
                servedOnServer = backend != null,
                externallyReachable = false,
                configRolledBack = false,
                failureCategory = fetched.failureCategory ?: SiteServingFailureCategory.EXTERNAL_UNREACHABLE,
                failureMessage = fetched.failureMessage ?: "Сайт недоступен снаружи",
            )
        }
    }

    private fun notVerified(
        backend: SiteServingBackend,
        plannedUrl: String,
        category: SiteServingFailureCategory,
        message: String,
    ) = SiteServingOutcome(backend, plannedUrl, null, false, false, false, category, message)

    private fun categoryOf(error: Throwable): SiteServingFailureCategory {
        val text = (error.message ?: "").lowercase()
        return when {
            "dns" in text -> SiteServingFailureCategory.DNS
            "tls" in text || "certificate" in text || "сертификат" in text -> SiteServingFailureCategory.CERTIFICATE
            "nginx" in text && ("missing" in text || "not installed" in text || "executable" in text) ->
                SiteServingFailureCategory.BACKEND_INCOMPATIBLE
            "reload" in text -> SiteServingFailureCategory.RELOAD_FAILED
            "syntax" in text -> SiteServingFailureCategory.CONFIG_INVALID
            "port" in text || "listen" in text -> SiteServingFailureCategory.PORT_CONFLICT
            else -> SiteServingFailureCategory.SERVING_VERIFICATION
        }
    }

    companion object {
        fun plannedNginxUrl(preparation: SiteDeployerLocalPreparationResult): String = plannedNginxUrl(
            preparation,
            https = preparation.remoteDeployPlan.certificate.mode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
        )

        fun plannedNginxUrl(preparation: SiteDeployerLocalPreparationResult, https: Boolean): String {
            val scheme = if (https) "https" else "http"
            val port = preparation.serviceBinding.port
            val domain = preparation.serviceBinding.domain.trim().lowercase()
            val defaultPort = if (https) 443 else 80
            return if (port == defaultPort) "$scheme://$domain/" else "$scheme://$domain:$port/"
        }
    }
}

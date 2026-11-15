package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteDeployerRemoteTreeExpectation
import com.velumtegra.xuimobile.core.site.SiteDeploymentCancellationSignal
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinator
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinatorResult
import com.velumtegra.xuimobile.core.site.SiteDeploymentRemoteRuntime
import com.velumtegra.xuimobile.core.site.SiteDeploymentStateSink
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentCoordinatorInvocationAuthorization
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPlan
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPreflight
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightStatus
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportAuthorization
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportBoundary
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportCapabilities
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportOutcome
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPolicy
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportResult
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportSource
import java.security.MessageDigest

/**
 * Phase 11.80 is the first production-shaped integration that invokes the already-existing
 * SiteDeploymentCoordinator under the accepted Phase 11.18/11.19 authorization chain and the
 * Android durable coordinator-invocation replay fence.
 *
 * Audit note: the Phase 11.68-11.79 HTTP/DNS proofs are post-publication verification boundaries,
 * so using one of those runtime proofs as a prerequisite for the same deployment would be circular.
 * Phase 11.80 therefore integrates the pre-deployment coordinator path only. A later end-to-end
 * phase must run the already-accepted web-serving verification chain over this coordinator output.
 *
 * The coordinator runtime below adds no remote primitive. Its transport execute() delegates exactly
 * once to the already accepted Phase 11.55 static-file transaction (11.52 staging, 11.53 commit /
 * rollback and 11.54 residual cleanup). There is no automatic retry.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun admit(
        invocationAuthorization: SiteProductionDeploymentCoordinatorInvocationAuthorization,
        runtimeMutationRequest: SiteProductionDeploymentRuntimeMutationRequest,
        preparation: SiteDeployerLocalPreparationResult,
        serverAccess: ServerAccess,
        evaluatedAtEpochMillis: Long,
    ): SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentRuntimeMutationBoundary.validateForCoordinatorInvocation(
            authorization = invocationAuthorization,
            request = runtimeMutationRequest,
            invokedAtEpochMillis = evaluatedAtEpochMillis,
        )
        val executionRequest = runtimeMutationRequest.executionRequest
        val executionAuthorization = runtimeMutationRequest.executionAuthorization
        require(executionRequest.coordinatorRequest.exportPlan == preparation.previewExport.export) {
            "Coordinator export plan differs from the exact local preparation"
        }
        require(executionRequest.coordinatorRequest.remoteRequest.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity) {
            "Coordinator remote host differs from the exact local preparation"
        }
        require(executionAuthorization.deploymentPlanSha256 == preparation.remoteDeployPlan.deploymentPlanSha256) {
            "Execution authorization deployment plan differs from the exact local preparation"
        }
        require(executionAuthorization.sourceTreeSha256 == preparation.remoteDeployPlan.sourceTreeSha256) {
            "Execution authorization source tree differs from the exact local preparation"
        }
        require(executionAuthorization.exportPlanSha256 == preparation.previewExport.export.manifest.planSha256) {
            "Execution authorization export plan digest differs from the exact local preparation"
        }
        require(serverAccess.endpoint.host == preparation.remoteDeployPlan.remoteHostIdentity) {
            "Coordinator ServerAccess host differs from the exact local preparation"
        }
        require(runtimeMutationRequest.runtimeIdentity.remoteHostIdentity == serverAccess.endpoint.host) {
            "Runtime identity host differs from coordinator ServerAccess"
        }
        require(executionAuthorization.candidateTransportAuthorizationSha256 ==
            SiteRemoteTransportBoundary.authorize(
                plan = preparation.remoteDeployPlan,
                preflight = SiteRemoteDeployPreflight.evaluate(
                    preparation.remoteDeployPlan,
                    executionRequest.coordinatorRequest.trust,
                    executionRequest.readinessRequest.remoteObservation,
                ),
                capabilities = executionRequest.transportCapabilities,
            ).authorizationSha256,
        ) { "Candidate transport authorization no longer matches exact coordinator inputs" }

        val base = SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmissionStatus
                .READY_FOR_ONE_EXISTING_COORDINATOR_INVOCATION,
            invocationAuthorizationSha256 = invocationAuthorization.invocationAuthorizationSha256,
            executionAuthorizationSha256 = executionAuthorization.executionAuthorizationSha256,
            coordinatorRequestSha256 = invocationAuthorization.coordinatorRequestSha256,
            runtimeIdentitySha256 = invocationAuthorization.runtimeIdentitySha256,
            permitSha256 = invocationAuthorization.permitSha256,
            candidateTransportAuthorizationSha256 = executionAuthorization.candidateTransportAuthorizationSha256,
            capabilityProfileSha256 = executionAuthorization.capabilityProfileSha256,
            localPreparationSha256 = preparation.preparationSha256,
            deploymentPlanSha256 = preparation.remoteDeployPlan.deploymentPlanSha256,
            sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            coordinatorInvocationId = invocationAuthorization.coordinatorInvocationId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            permitExpiresAtEpochMillis = invocationAuthorization.permitExpiresAtEpochMillis,
            requiresDurableCoordinatorInvocationFence = true,
            delegatesToExistingCoordinator = true,
            delegatesTransportToAcceptedPhase1155Transaction = true,
            addsNewRemoteMutationPrimitive = false,
            automaticRetryAuthorized = false,
            arbitraryCommandAuthorized = false,
            exposesDeployUiAction = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun executeOnce(
        admission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
        invocationAuthorization: SiteProductionDeploymentCoordinatorInvocationAuthorization,
        runtimeMutationRequest: SiteProductionDeploymentRuntimeMutationRequest,
        preparation: SiteDeployerLocalPreparationResult,
        serverAccess: ServerAccess,
        previousTargetTree: SiteDeployerRemoteTreeExpectation? = null,
        credentialProvider: SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider,
        replayFence: SiteProductionDeploymentDurableReplayFence,
        executedAtEpochMillis: Long,
        cancellation: SiteDeploymentCancellationSignal = SiteDeploymentCancellationSignal { false },
        stateSink: SiteDeploymentStateSink = SiteDeploymentStateSink { },
    ): SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult {
        // Rebuild the admission at the exact time it was originally evaluated so the admission
        // digest remains an immutable binding of the approved inputs. Freshness is checked
        // separately at the real execution time immediately below.
        val rebuilt = admit(
            invocationAuthorization = invocationAuthorization,
            runtimeMutationRequest = runtimeMutationRequest,
            preparation = preparation,
            serverAccess = serverAccess,
            evaluatedAtEpochMillis = admission.evaluatedAtEpochMillis,
        )
        require(rebuilt == admission) { "Coordinator admission is stale or bound to different inputs" }
        SiteProductionDeploymentRuntimeMutationBoundary.validateForCoordinatorInvocation(
            authorization = invocationAuthorization,
            request = runtimeMutationRequest,
            invokedAtEpochMillis = executedAtEpochMillis,
        )
        require(executedAtEpochMillis <= admission.permitExpiresAtEpochMillis) {
            "Coordinator invocation permit expired before execution"
        }

        // Counteraction before action: once this durable marker is created there is never a blind
        // retry of the same coordinator authorization, even if the process dies during mutation.
        require(
            replayFence.coordinatorInvocationUsePort().consumeOnce(
                invocationAuthorization.invocationAuthorizationSha256,
            ),
        ) { "Coordinator invocation authorization was already used or replay fence failed closed" }

        val runtime = Phase1155CoordinatorRuntime(
            preparation = preparation,
            serverAccess = serverAccess,
            previousTargetTree = previousTargetTree,
            credentialProvider = credentialProvider,
            replayFence = replayFence,
            runtimeMutationRequest = runtimeMutationRequest,
        )
        val coordinatorResult = SiteDeploymentCoordinator.deploy(
            request = runtimeMutationRequest.executionRequest.coordinatorRequest,
            runtime = runtime,
            cancellation = cancellation,
            stateSink = stateSink,
        )
        val transaction = requireNotNull(runtime.transactionResult) {
            "Coordinator completed without reaching the accepted Phase 11.55 transaction"
        }
        SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary.validateResult(transaction)

        val status = when (coordinatorResult) {
            is SiteDeploymentCoordinatorResult.Committed -> {
                require(transaction.outcome == SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN)
                require(coordinatorResult.transport.outcome == SiteRemoteTransportOutcome.COMMITTED)
                SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                    .COORDINATOR_COMMITTED_EXACT_STATIC_TREE
            }
            is SiteDeploymentCoordinatorResult.RolledBack -> {
                require(transaction.outcome == SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.ROLLED_BACK_CLEAN)
                require(coordinatorResult.transport.outcome == SiteRemoteTransportOutcome.ROLLED_BACK)
                SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                    .COORDINATOR_ROLLED_BACK_CLEAN
            }
            is SiteDeploymentCoordinatorResult.Blocked -> error("Coordinator unexpectedly blocked after exact admission")
            is SiteDeploymentCoordinatorResult.Cancelled -> error("Coordinator unexpectedly cancelled after invocation fence consumption")
        }
        val base = SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status = status,
            admissionSha256 = admission.admissionSha256,
            invocationAuthorizationSha256 = invocationAuthorization.invocationAuthorizationSha256,
            executionAuthorizationSha256 = runtimeMutationRequest.executionAuthorization.executionAuthorizationSha256,
            coordinatorRequestSha256 = invocationAuthorization.coordinatorRequestSha256,
            localPreparationSha256 = preparation.preparationSha256,
            deploymentPlanSha256 = preparation.remoteDeployPlan.deploymentPlanSha256,
            candidateTransportAuthorizationSha256 = runtimeMutationRequest.executionAuthorization
                .candidateTransportAuthorizationSha256,
            staticFileTransactionResult = transaction,
            coordinatorResult = coordinatorResult,
            coordinatorInvocationFenceConsumed = true,
            coordinatorInvoked = true,
            existingCoordinatorInvocationCount = 1,
            acceptedPhase1155TransactionDelegated = true,
            newRemoteMutationPrimitiveAdded = false,
            automaticRetryPerformed = false,
            arbitraryCommandInputAccepted = false,
            exposesDeployUiAction = false,
            executedAtEpochMillis = executedAtEpochMillis,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also {
            validateExecutionResult(it, admission, preparation)
        }
    }

    fun validateAdmission(admission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(admission.status == SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmissionStatus
            .READY_FOR_ONE_EXISTING_COORDINATOR_INVOCATION)
        listOf(
            admission.invocationAuthorizationSha256,
            admission.executionAuthorizationSha256,
            admission.coordinatorRequestSha256,
            admission.runtimeIdentitySha256,
            admission.permitSha256,
            admission.candidateTransportAuthorizationSha256,
            admission.capabilityProfileSha256,
            admission.localPreparationSha256,
            admission.deploymentPlanSha256,
            admission.sourceTreeSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(admission.remoteHostIdentity.isNotBlank())
        require(admission.targetRoot.startsWith("/"))
        require(admission.coordinatorInvocationId.isNotBlank())
        require(admission.evaluatedAtEpochMillis >= 0L)
        require(admission.evaluatedAtEpochMillis <= admission.permitExpiresAtEpochMillis)
        require(admission.requiresDurableCoordinatorInvocationFence)
        require(admission.delegatesToExistingCoordinator)
        require(admission.delegatesTransportToAcceptedPhase1155Transaction)
        require(!admission.addsNewRemoteMutationPrimitive)
        require(!admission.automaticRetryAuthorized)
        require(!admission.arbitraryCommandAuthorized)
        require(!admission.exposesDeployUiAction)
        require(admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = "")))
    }

    fun validateExecutionResult(
        result: SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult,
        admission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
        preparation: SiteDeployerLocalPreparationResult,
    ) {
        validateAdmission(admission)
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        require(result.contractVersion == CONTRACT_VERSION)
        require(result.admissionSha256 == admission.admissionSha256)
        require(result.invocationAuthorizationSha256 == admission.invocationAuthorizationSha256)
        require(result.executionAuthorizationSha256 == admission.executionAuthorizationSha256)
        require(result.coordinatorRequestSha256 == admission.coordinatorRequestSha256)
        require(result.localPreparationSha256 == admission.localPreparationSha256)
        require(result.localPreparationSha256 == preparation.preparationSha256)
        require(result.deploymentPlanSha256 == preparation.remoteDeployPlan.deploymentPlanSha256)
        require(result.candidateTransportAuthorizationSha256 == admission.candidateTransportAuthorizationSha256)
        SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary
            .validateResult(result.staticFileTransactionResult)
        require(result.staticFileTransactionResult.preparationSha256 == preparation.preparationSha256)
        require(result.coordinatorInvocationFenceConsumed)
        require(result.coordinatorInvoked)
        require(result.existingCoordinatorInvocationCount == 1)
        require(result.acceptedPhase1155TransactionDelegated)
        require(!result.newRemoteMutationPrimitiveAdded)
        require(!result.automaticRetryPerformed)
        require(!result.arbitraryCommandInputAccepted)
        require(!result.exposesDeployUiAction)
        require(result.executedAtEpochMillis >= admission.evaluatedAtEpochMillis)
        require(sha256.matches(result.executionResultSha256))
        require(result.executionResultSha256 == executionResultSha256(result.copy(executionResultSha256 = "")))
        when (result.status) {
            SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                .COORDINATOR_COMMITTED_EXACT_STATIC_TREE -> {
                require(result.coordinatorResult is SiteDeploymentCoordinatorResult.Committed)
                require(result.staticFileTransactionResult.outcome ==
                    SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN)
                require(result.staticFileTransactionResult.finalTargetTreeSha256 == preparation.remoteDeployPlan.sourceTreeSha256)
            }
            SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                .COORDINATOR_ROLLED_BACK_CLEAN -> {
                require(result.coordinatorResult is SiteDeploymentCoordinatorResult.RolledBack)
                require(result.staticFileTransactionResult.outcome ==
                    SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.ROLLED_BACK_CLEAN)
            }
        }
    }

    /** Zero-network deterministic seam used by JVM tests. */
    internal fun admissionSha256ForTest(
        admissionWithoutSha: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
    ): String = admissionSha256(admissionWithoutSha.copy(admissionSha256 = ""))

    private class Phase1155CoordinatorRuntime(
        private val preparation: SiteDeployerLocalPreparationResult,
        private val serverAccess: ServerAccess,
        private val previousTargetTree: SiteDeployerRemoteTreeExpectation?,
        private val credentialProvider: SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider,
        private val replayFence: SiteProductionDeploymentDurableReplayFence,
        private val runtimeMutationRequest: SiteProductionDeploymentRuntimeMutationRequest,
    ) : SiteDeploymentRemoteRuntime {
        override val capabilities: SiteRemoteTransportCapabilities
            get() = runtimeMutationRequest.executionRequest.transportCapabilities

        var transactionResult: SiteProductionDeploymentRealVpsStaticFileTransactionResult? = null
            private set

        override suspend fun observe(plan: SiteRemoteDeployPlan): SiteRemotePreflightObservation {
            require(plan.deploymentPlanSha256 == preparation.remoteDeployPlan.deploymentPlanSha256) {
                "Coordinator rebuilt a deployment plan different from exact local preparation"
            }
            val observation = runtimeMutationRequest.executionRequest.readinessRequest.remoteObservation
            val report = SiteRemoteDeployPreflight.evaluate(
                plan,
                runtimeMutationRequest.executionRequest.coordinatorRequest.trust,
                observation,
            )
            require(report.status == SiteRemotePreflightStatus.READY) {
                "Approved coordinator preflight evidence is no longer READY"
            }
            require(report.preflightSha256 == runtimeMutationRequest.executionAuthorization.preflightSha256) {
                "Coordinator preflight differs from execution authorization"
            }
            return observation
        }

        override suspend fun execute(
            authorization: SiteRemoteTransportAuthorization,
            source: SiteRemoteTransportSource,
        ): SiteRemoteTransportResult {
            require(transactionResult == null) { "Coordinator transport execute() was invoked more than once" }
            require(authorization.authorizationSha256 == runtimeMutationRequest.executionAuthorization
                .candidateTransportAuthorizationSha256) {
                "Coordinator rebuilt transport authorization differs from execution authorization"
            }
            require(authorization.deploymentPlanSha256 == preparation.remoteDeployPlan.deploymentPlanSha256)
            require(authorization.sourceTreeSha256 == preparation.remoteDeployPlan.sourceTreeSha256)
            require(authorization.capabilityProfileSha256 == runtimeMutationRequest.executionAuthorization
                .capabilityProfileSha256)
            verifyCoordinatorSource(source)

            val transaction = SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary.executeOnce(
                request = SiteProductionDeploymentRealVpsStaticFileTransactionRequest(
                    preparation = preparation,
                    serverAccess = serverAccess,
                    previousTargetTree = previousTargetTree,
                ),
                credentialProvider = credentialProvider,
                replayFence = replayFence,
            ).also(SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary::validateResult)
            transactionResult = transaction
            return when (transaction.outcome) {
                SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN ->
                    SiteRemoteTransportResult(
                        authorizationSha256 = authorization.authorizationSha256,
                        outcome = SiteRemoteTransportOutcome.COMMITTED,
                        uploadedFileCount = authorization.fileCount,
                        uploadedBytes = authorization.totalBytes,
                        publishedTreeSha256 = authorization.sourceTreeSha256,
                        rollbackPerformed = false,
                    )
                SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.ROLLED_BACK_CLEAN ->
                    SiteRemoteTransportResult(
                        authorizationSha256 = authorization.authorizationSha256,
                        outcome = SiteRemoteTransportOutcome.ROLLED_BACK,
                        uploadedFileCount = authorization.fileCount,
                        uploadedBytes = authorization.totalBytes,
                        publishedTreeSha256 = null,
                        rollbackPerformed = true,
                    )
            }.also { SiteRemoteTransportPolicy.validateResult(authorization, it) }
        }

        private fun verifyCoordinatorSource(source: SiteRemoteTransportSource) {
            preparation.previewExport.export.entries.forEach { entry ->
                val bytes = source.read(entry.path)
                require(bytes.size == entry.byteSize) { "Coordinator source byte count changed: ${entry.path}" }
                require(sha256Bytes(bytes) == entry.sha256) {
                    "Coordinator source SHA-256 changed: ${entry.path}"
                }
            }
        }
    }

    private fun admissionSha256(
        admissionWithoutSha: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
    ): String = digest(
        buildString {
            append("contractVersion=").append(admissionWithoutSha.contractVersion).append('\n')
            append("status=").append(admissionWithoutSha.status.name).append('\n')
            append("invocationAuthorizationSha256=").append(admissionWithoutSha.invocationAuthorizationSha256).append('\n')
            append("executionAuthorizationSha256=").append(admissionWithoutSha.executionAuthorizationSha256).append('\n')
            append("coordinatorRequestSha256=").append(admissionWithoutSha.coordinatorRequestSha256).append('\n')
            append("runtimeIdentitySha256=").append(admissionWithoutSha.runtimeIdentitySha256).append('\n')
            append("permitSha256=").append(admissionWithoutSha.permitSha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(admissionWithoutSha.candidateTransportAuthorizationSha256).append('\n')
            append("capabilityProfileSha256=").append(admissionWithoutSha.capabilityProfileSha256).append('\n')
            append("localPreparationSha256=").append(admissionWithoutSha.localPreparationSha256).append('\n')
            append("deploymentPlanSha256=").append(admissionWithoutSha.deploymentPlanSha256).append('\n')
            append("sourceTreeSha256=").append(admissionWithoutSha.sourceTreeSha256).append('\n')
            append("remoteHostIdentity=").append(admissionWithoutSha.remoteHostIdentity).append('\n')
            append("targetRoot=").append(admissionWithoutSha.targetRoot).append('\n')
            append("coordinatorInvocationId=").append(admissionWithoutSha.coordinatorInvocationId).append('\n')
            append("evaluatedAtEpochMillis=").append(admissionWithoutSha.evaluatedAtEpochMillis).append('\n')
            append("permitExpiresAtEpochMillis=").append(admissionWithoutSha.permitExpiresAtEpochMillis).append('\n')
            append("requiresDurableCoordinatorInvocationFence=").append(admissionWithoutSha.requiresDurableCoordinatorInvocationFence).append('\n')
            append("delegatesToExistingCoordinator=").append(admissionWithoutSha.delegatesToExistingCoordinator).append('\n')
            append("delegatesTransportToAcceptedPhase1155Transaction=").append(admissionWithoutSha.delegatesTransportToAcceptedPhase1155Transaction).append('\n')
            append("addsNewRemoteMutationPrimitive=").append(admissionWithoutSha.addsNewRemoteMutationPrimitive).append('\n')
            append("automaticRetryAuthorized=").append(admissionWithoutSha.automaticRetryAuthorized).append('\n')
            append("arbitraryCommandAuthorized=").append(admissionWithoutSha.arbitraryCommandAuthorized).append('\n')
            append("exposesDeployUiAction=").append(admissionWithoutSha.exposesDeployUiAction).append('\n')
        },
    )

    private fun executionResultSha256(
        resultWithoutSha: SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult,
    ): String = digest(
        buildString {
            append("contractVersion=").append(resultWithoutSha.contractVersion).append('\n')
            append("status=").append(resultWithoutSha.status.name).append('\n')
            append("admissionSha256=").append(resultWithoutSha.admissionSha256).append('\n')
            append("invocationAuthorizationSha256=").append(resultWithoutSha.invocationAuthorizationSha256).append('\n')
            append("executionAuthorizationSha256=").append(resultWithoutSha.executionAuthorizationSha256).append('\n')
            append("coordinatorRequestSha256=").append(resultWithoutSha.coordinatorRequestSha256).append('\n')
            append("localPreparationSha256=").append(resultWithoutSha.localPreparationSha256).append('\n')
            append("deploymentPlanSha256=").append(resultWithoutSha.deploymentPlanSha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(resultWithoutSha.candidateTransportAuthorizationSha256).append('\n')
            append("transactionOutcome=").append(resultWithoutSha.staticFileTransactionResult.outcome.name).append('\n')
            append("stagingProofSha256=").append(resultWithoutSha.staticFileTransactionResult.stagingProof.executionProofSha256).append('\n')
            append("commitProofSha256=").append(resultWithoutSha.staticFileTransactionResult.commitProof.executionProofSha256).append('\n')
            append("cleanupProofSha256=").append(resultWithoutSha.staticFileTransactionResult.cleanupProof?.executionProofSha256 ?: "").append('\n')
            append("finalTargetTreeSha256=").append(resultWithoutSha.staticFileTransactionResult.finalTargetTreeSha256 ?: "").append('\n')
            append("coordinatorInvocationFenceConsumed=").append(resultWithoutSha.coordinatorInvocationFenceConsumed).append('\n')
            append("coordinatorInvoked=").append(resultWithoutSha.coordinatorInvoked).append('\n')
            append("existingCoordinatorInvocationCount=").append(resultWithoutSha.existingCoordinatorInvocationCount).append('\n')
            append("acceptedPhase1155TransactionDelegated=").append(resultWithoutSha.acceptedPhase1155TransactionDelegated).append('\n')
            append("newRemoteMutationPrimitiveAdded=").append(resultWithoutSha.newRemoteMutationPrimitiveAdded).append('\n')
            append("automaticRetryPerformed=").append(resultWithoutSha.automaticRetryPerformed).append('\n')
            append("arbitraryCommandInputAccepted=").append(resultWithoutSha.arbitraryCommandInputAccepted).append('\n')
            append("exposesDeployUiAction=").append(resultWithoutSha.exposesDeployUiAction).append('\n')
            append("executedAtEpochMillis=").append(resultWithoutSha.executedAtEpochMillis).append('\n')
        },
    )

    private fun sha256Bytes(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value)
        .joinToString("") { "%02x".format(it) }

    private fun digest(value: String): String = sha256Bytes(value.toByteArray(Charsets.UTF_8))
}


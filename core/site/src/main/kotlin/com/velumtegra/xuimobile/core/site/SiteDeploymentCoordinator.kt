package com.velumtegra.xuimobile.core.site

object SiteDeploymentCoordinator {
    suspend fun deploy(
        request: SiteDeploymentCoordinatorRequest,
        runtime: SiteDeploymentRemoteRuntime,
        cancellation: SiteDeploymentCancellationSignal = SiteDeploymentCancellationSignal { false },
        stateSink: SiteDeploymentStateSink = SiteDeploymentStateSink { },
    ): SiteDeploymentCoordinatorResult {
        SiteLocalExportPolicy.validatePlan(request.exportPlan)
        SiteRemoteDeployPolicy.validateRequest(request.remoteRequest)
        SiteRemotePreflightPolicy.validateTrust(request.trust)
        SiteRemoteTransportPolicy.validateCapabilities(runtime.capabilities)

        val state = StateMachine(stateSink)
        state.move(SiteDeploymentCoordinatorState.STARTED)
        if (cancellation.isCancellationRequested()) {
            state.move(SiteDeploymentCoordinatorState.CANCELLED)
            return SiteDeploymentCoordinatorResult.Cancelled(SiteDeploymentCoordinatorStage.EXPORT)
        }

        val receipt = runStage(SiteDeploymentCoordinatorStage.EXPORT, state) {
            state.move(SiteDeploymentCoordinatorState.EXPORTING)
            SiteLocalExportAdapter.export(request.exportPlan, request.localOutputRoot).also {
                state.move(SiteDeploymentCoordinatorState.EXPORTED)
            }
        }
        if (cancellation.isCancellationRequested()) {
            state.move(SiteDeploymentCoordinatorState.CANCELLED)
            return SiteDeploymentCoordinatorResult.Cancelled(
                beforeStage = SiteDeploymentCoordinatorStage.PLAN,
                receipt = receipt,
            )
        }

        val plan = runStage(SiteDeploymentCoordinatorStage.PLAN, state) {
            SiteRemoteDeployBoundary.prepare(request.exportPlan, receipt, request.remoteRequest).also {
                state.move(
                    SiteDeploymentCoordinatorState.PLAN_PREPARED,
                    deploymentPlanSha256 = it.deploymentPlanSha256,
                )
            }
        }
        if (cancellation.isCancellationRequested()) {
            state.move(SiteDeploymentCoordinatorState.CANCELLED, plan.deploymentPlanSha256)
            return SiteDeploymentCoordinatorResult.Cancelled(
                beforeStage = SiteDeploymentCoordinatorStage.PREFLIGHT,
                receipt = receipt,
                plan = plan,
            )
        }

        val preflight = runStage(SiteDeploymentCoordinatorStage.PREFLIGHT, state, plan.deploymentPlanSha256) {
            state.move(SiteDeploymentCoordinatorState.PREFLIGHTING, plan.deploymentPlanSha256)
            val observation = runtime.observe(plan)
            SiteRemoteDeployPreflight.evaluate(plan, request.trust, observation)
        }
        if (preflight.status == SiteRemotePreflightStatus.BLOCKED) {
            state.move(
                SiteDeploymentCoordinatorState.PREFLIGHT_BLOCKED,
                plan.deploymentPlanSha256,
                preflight.preflightSha256,
            )
            return SiteDeploymentCoordinatorResult.Blocked(receipt, plan, preflight)
        }
        state.move(
            SiteDeploymentCoordinatorState.PREFLIGHT_READY,
            plan.deploymentPlanSha256,
            preflight.preflightSha256,
        )
        if (cancellation.isCancellationRequested()) {
            state.move(
                SiteDeploymentCoordinatorState.CANCELLED,
                plan.deploymentPlanSha256,
                preflight.preflightSha256,
            )
            return SiteDeploymentCoordinatorResult.Cancelled(
                beforeStage = SiteDeploymentCoordinatorStage.AUTHORIZATION,
                receipt = receipt,
                plan = plan,
                preflight = preflight,
            )
        }

        val authorization = runStage(
            SiteDeploymentCoordinatorStage.AUTHORIZATION,
            state,
            plan.deploymentPlanSha256,
            preflight.preflightSha256,
        ) {
            state.move(
                SiteDeploymentCoordinatorState.AUTHORIZING,
                plan.deploymentPlanSha256,
                preflight.preflightSha256,
            )
            SiteRemoteTransportBoundary.authorize(plan, preflight, runtime.capabilities).also {
                state.move(
                    SiteDeploymentCoordinatorState.AUTHORIZED,
                    plan.deploymentPlanSha256,
                    preflight.preflightSha256,
                    it.authorizationSha256,
                )
            }
        }
        if (cancellation.isCancellationRequested()) {
            state.move(
                SiteDeploymentCoordinatorState.CANCELLED,
                plan.deploymentPlanSha256,
                preflight.preflightSha256,
                authorization.authorizationSha256,
            )
            return SiteDeploymentCoordinatorResult.Cancelled(
                beforeStage = SiteDeploymentCoordinatorStage.TRANSPORT,
                receipt = receipt,
                plan = plan,
                preflight = preflight,
                authorization = authorization,
            )
        }

        // Cancellation is intentionally no longer polled after DEPLOYING begins. The bounded
        // transport executor owns the transaction and must reach a proven COMMITTED or ROLLED_BACK
        // state instead of being interrupted between remote mutations.
        val transport = runStage(
            SiteDeploymentCoordinatorStage.TRANSPORT,
            state,
            plan.deploymentPlanSha256,
            preflight.preflightSha256,
            authorization.authorizationSha256,
        ) {
            state.move(
                SiteDeploymentCoordinatorState.DEPLOYING,
                plan.deploymentPlanSha256,
                preflight.preflightSha256,
                authorization.authorizationSha256,
            )
            require(
                SiteRemoteTransportPolicy.capabilityProfileSha256(runtime.capabilities) == authorization.capabilityProfileSha256,
            ) { "Remote runtime capability profile changed after authorization" }
            runtime.execute(authorization, sourceFor(request.exportPlan)).also { result ->
                SiteRemoteTransportPolicy.validateResult(authorization, result)
            }
        }
        return when (transport.outcome) {
            SiteRemoteTransportOutcome.COMMITTED -> {
                state.move(
                    SiteDeploymentCoordinatorState.COMMITTED,
                    plan.deploymentPlanSha256,
                    preflight.preflightSha256,
                    authorization.authorizationSha256,
                )
                SiteDeploymentCoordinatorResult.Committed(receipt, plan, preflight, authorization, transport)
            }
            SiteRemoteTransportOutcome.ROLLED_BACK -> {
                state.move(
                    SiteDeploymentCoordinatorState.ROLLED_BACK,
                    plan.deploymentPlanSha256,
                    preflight.preflightSha256,
                    authorization.authorizationSha256,
                )
                SiteDeploymentCoordinatorResult.RolledBack(receipt, plan, preflight, authorization, transport)
            }
        }
    }

    private fun sourceFor(plan: SiteExportPlan): SiteRemoteTransportSource {
        val entries = plan.entries.associateBy(SiteExportEntry::path)
        require(entries.size == plan.entries.size) { "Export plan contains duplicate source paths" }
        return SiteRemoteTransportSource { relativePath ->
            val entry = requireNotNull(entries[relativePath]) { "Transport requested an unknown export path: $relativePath" }
            val bytes = entry.content.encodeToByteArray()
            require(bytes.size == entry.byteSize) { "Export source byte count changed: $relativePath" }
            require(SiteBundleDigest.sha256(bytes) == entry.sha256) { "Export source SHA-256 changed: $relativePath" }
            bytes.copyOf()
        }
    }

    private suspend fun <T> runStage(
        stage: SiteDeploymentCoordinatorStage,
        state: StateMachine,
        deploymentPlanSha256: String? = null,
        preflightSha256: String? = null,
        authorizationSha256: String? = null,
        block: suspend () -> T,
    ): T = try {
        block()
    } catch (failure: Throwable) {
        state.move(
            SiteDeploymentCoordinatorState.FAILED,
            deploymentPlanSha256,
            preflightSha256,
            authorizationSha256,
        )
        throw SiteDeploymentCoordinatorException(stage, failure)
    }

    private class StateMachine(
        private val sink: SiteDeploymentStateSink,
    ) {
        private var current: SiteDeploymentCoordinatorState? = null

        fun move(
            next: SiteDeploymentCoordinatorState,
            deploymentPlanSha256: String? = null,
            preflightSha256: String? = null,
            authorizationSha256: String? = null,
        ) {
            require(next in allowedNext(current)) { "Invalid deployment state transition: $current -> $next" }
            current = next
            // Progress observers are best-effort. They must never be able to turn a committed
            // remote mutation into an apparent deployment failure by throwing after the fact.
            runCatching {
                sink.onState(
                    SiteDeploymentCoordinatorEvent(
                        state = next,
                        deploymentPlanSha256 = deploymentPlanSha256,
                        preflightSha256 = preflightSha256,
                        authorizationSha256 = authorizationSha256,
                    ),
                )
            }
        }

        private fun allowedNext(current: SiteDeploymentCoordinatorState?): Set<SiteDeploymentCoordinatorState> = when (current) {
            null -> setOf(SiteDeploymentCoordinatorState.STARTED)
            SiteDeploymentCoordinatorState.STARTED -> setOf(
                SiteDeploymentCoordinatorState.EXPORTING,
                SiteDeploymentCoordinatorState.CANCELLED,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.EXPORTING -> setOf(
                SiteDeploymentCoordinatorState.EXPORTED,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.EXPORTED -> setOf(
                SiteDeploymentCoordinatorState.PLAN_PREPARED,
                SiteDeploymentCoordinatorState.CANCELLED,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.PLAN_PREPARED -> setOf(
                SiteDeploymentCoordinatorState.PREFLIGHTING,
                SiteDeploymentCoordinatorState.CANCELLED,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.PREFLIGHTING -> setOf(
                SiteDeploymentCoordinatorState.PREFLIGHT_READY,
                SiteDeploymentCoordinatorState.PREFLIGHT_BLOCKED,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.PREFLIGHT_READY -> setOf(
                SiteDeploymentCoordinatorState.AUTHORIZING,
                SiteDeploymentCoordinatorState.CANCELLED,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.AUTHORIZING -> setOf(
                SiteDeploymentCoordinatorState.AUTHORIZED,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.AUTHORIZED -> setOf(
                SiteDeploymentCoordinatorState.DEPLOYING,
                SiteDeploymentCoordinatorState.CANCELLED,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.DEPLOYING -> setOf(
                SiteDeploymentCoordinatorState.COMMITTED,
                SiteDeploymentCoordinatorState.ROLLED_BACK,
                SiteDeploymentCoordinatorState.FAILED,
            )
            SiteDeploymentCoordinatorState.PREFLIGHT_BLOCKED,
            SiteDeploymentCoordinatorState.COMMITTED,
            SiteDeploymentCoordinatorState.ROLLED_BACK,
            SiteDeploymentCoordinatorState.CANCELLED,
            SiteDeploymentCoordinatorState.FAILED,
            -> emptySet()
        }
    }
}

package com.velumtegra.xuimobile.core.site

object SiteProductionDeploymentFixtureCoordinatorInvocationBridge {
    private val fixtureId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun invoke(
        request: SiteProductionDeploymentFixtureInvocationRequest,
        runtime: SiteProductionDeploymentFixtureRuntime,
        invocationUsePort: SiteProductionDeploymentCoordinatorInvocationUsePort,
        cancellation: SiteDeploymentCancellationSignal = SiteDeploymentCancellationSignal { false },
        stateSink: SiteDeploymentStateSink = SiteDeploymentStateSink { },
    ): SiteProductionDeploymentFixtureInvocationReceipt {
        val authorization = request.invocationAuthorization
        val mutationRequest = request.runtimeMutationRequest
        val executionRequest = mutationRequest.executionRequest
        val executionAuthorization = mutationRequest.executionAuthorization

        SiteProductionDeploymentRuntimeMutationBoundary.validateForCoordinatorInvocation(
            authorization = authorization,
            request = mutationRequest,
            invokedAtEpochMillis = request.invokedAtEpochMillis,
        )

        val binding = runtime.fixtureBinding
        require(fixtureId.matches(binding.fixtureId)) { "Fixture runtime id must be a canonical 8..128 character identifier" }
        require(binding.fixtureOnly) { "Phase 11.20 bridge accepts fixture-only runtimes" }
        require(!binding.productionTransportEnabled) { "Fixture runtime must keep production transport disabled" }
        require(!binding.realVpsAccessAllowed) { "Fixture runtime must forbid real VPS access" }
        require(binding.runtimeIdentity == mutationRequest.runtimeIdentity) {
            "Fixture runtime identity differs from the approved runtime identity"
        }
        require(runtime.capabilities == executionRequest.transportCapabilities) {
            "Fixture runtime capabilities differ from the approved execution capabilities"
        }
        require(
            SiteRemoteTransportPolicy.capabilityProfileSha256(runtime.capabilities) ==
                executionAuthorization.capabilityProfileSha256,
        ) { "Fixture runtime capability profile differs from execution authorization" }

        require(invocationUsePort.consumeOnce(authorization.invocationAuthorizationSha256)) {
            "Coordinator invocation authorization was already handed off or replay fence failed closed"
        }

        val guardedRuntime = ExactFixtureRuntime(
            delegate = runtime,
            request = executionRequest.coordinatorRequest,
            executionAuthorization = executionAuthorization,
        )
        val result = SiteDeploymentCoordinator.deploy(
            request = executionRequest.coordinatorRequest,
            runtime = guardedRuntime,
            cancellation = cancellation,
            stateSink = stateSink,
        )
        return SiteProductionDeploymentFixtureInvocationReceipt(
            fixtureId = binding.fixtureId,
            coordinatorInvocationId = authorization.coordinatorInvocationId,
            invocationAuthorizationSha256 = authorization.invocationAuthorizationSha256,
            invokedAtEpochMillis = request.invokedAtEpochMillis,
            fixtureOnly = true,
            productionTransportEnabled = false,
            realVpsAccessAllowed = false,
            coordinatorResult = result,
        )
    }

    private class ExactFixtureRuntime(
        private val delegate: SiteProductionDeploymentFixtureRuntime,
        private val request: SiteDeploymentCoordinatorRequest,
        private val executionAuthorization: SiteProductionDeploymentExecutionAuthorization,
    ) : SiteDeploymentRemoteRuntime {
        override val capabilities: SiteRemoteTransportCapabilities
            get() = delegate.capabilities

        override suspend fun observe(plan: SiteRemoteDeployPlan): SiteRemotePreflightObservation {
            require(plan.deploymentPlanSha256 == executionAuthorization.deploymentPlanSha256) {
                "Coordinator rebuilt a deployment plan that differs from execution authorization"
            }
            val observation = delegate.observe(plan)
            val preflight = SiteRemoteDeployPreflight.evaluate(plan, request.trust, observation)
            require(preflight.status == SiteRemotePreflightStatus.READY) {
                "Fixture observation is no longer READY"
            }
            require(preflight.preflightSha256 == executionAuthorization.preflightSha256) {
                "Fixture observation differs from approved preflight evidence"
            }
            return observation
        }

        override suspend fun execute(
            authorization: SiteRemoteTransportAuthorization,
            source: SiteRemoteTransportSource,
        ): SiteRemoteTransportResult {
            require(authorization.authorizationSha256 == executionAuthorization.candidateTransportAuthorizationSha256) {
                "Coordinator transport authorization differs from the approved candidate authorization"
            }
            require(authorization.capabilityProfileSha256 == executionAuthorization.capabilityProfileSha256) {
                "Coordinator transport capability profile differs from execution authorization"
            }
            return delegate.execute(authorization, source)
        }
    }
}

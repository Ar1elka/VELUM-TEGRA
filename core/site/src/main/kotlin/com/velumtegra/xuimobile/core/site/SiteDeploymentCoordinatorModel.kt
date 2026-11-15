package com.velumtegra.xuimobile.core.site

import java.nio.file.Path

data class SiteDeploymentCoordinatorRequest(
    val exportPlan: SiteExportPlan,
    val localOutputRoot: Path,
    val remoteRequest: SiteRemoteDeployRequest,
    val trust: SiteRemotePreflightTrust,
)

enum class SiteDeploymentCoordinatorStage {
    EXPORT,
    PLAN,
    PREFLIGHT,
    AUTHORIZATION,
    TRANSPORT,
}

enum class SiteDeploymentCoordinatorState {
    STARTED,
    EXPORTING,
    EXPORTED,
    PLAN_PREPARED,
    PREFLIGHTING,
    PREFLIGHT_READY,
    PREFLIGHT_BLOCKED,
    AUTHORIZING,
    AUTHORIZED,
    DEPLOYING,
    COMMITTED,
    ROLLED_BACK,
    CANCELLED,
    FAILED,
}

data class SiteDeploymentCoordinatorEvent(
    val state: SiteDeploymentCoordinatorState,
    val deploymentPlanSha256: String? = null,
    val preflightSha256: String? = null,
    val authorizationSha256: String? = null,
)

fun interface SiteDeploymentStateSink {
    fun onState(event: SiteDeploymentCoordinatorEvent)
}

fun interface SiteDeploymentCancellationSignal {
    fun isCancellationRequested(): Boolean
}

interface SiteDeploymentRemoteRuntime {
    val capabilities: SiteRemoteTransportCapabilities

    suspend fun observe(plan: SiteRemoteDeployPlan): SiteRemotePreflightObservation

    suspend fun execute(
        authorization: SiteRemoteTransportAuthorization,
        source: SiteRemoteTransportSource,
    ): SiteRemoteTransportResult
}

sealed interface SiteDeploymentCoordinatorResult {
    val receipt: SiteLocalExportReceipt?

    data class Committed(
        override val receipt: SiteLocalExportReceipt,
        val plan: SiteRemoteDeployPlan,
        val preflight: SiteRemotePreflightReport,
        val authorization: SiteRemoteTransportAuthorization,
        val transport: SiteRemoteTransportResult,
    ) : SiteDeploymentCoordinatorResult

    data class RolledBack(
        override val receipt: SiteLocalExportReceipt,
        val plan: SiteRemoteDeployPlan,
        val preflight: SiteRemotePreflightReport,
        val authorization: SiteRemoteTransportAuthorization,
        val transport: SiteRemoteTransportResult,
    ) : SiteDeploymentCoordinatorResult

    data class Blocked(
        override val receipt: SiteLocalExportReceipt,
        val plan: SiteRemoteDeployPlan,
        val preflight: SiteRemotePreflightReport,
    ) : SiteDeploymentCoordinatorResult

    data class Cancelled(
        val beforeStage: SiteDeploymentCoordinatorStage,
        override val receipt: SiteLocalExportReceipt? = null,
        val plan: SiteRemoteDeployPlan? = null,
        val preflight: SiteRemotePreflightReport? = null,
        val authorization: SiteRemoteTransportAuthorization? = null,
    ) : SiteDeploymentCoordinatorResult
}

class SiteDeploymentCoordinatorException(
    val stage: SiteDeploymentCoordinatorStage,
    cause: Throwable,
) : IllegalStateException("Site deployment failed during ${stage.name}", cause)

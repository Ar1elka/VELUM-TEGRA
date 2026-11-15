package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.runtime.ColdStartRecoveryPlan
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeReleaseResult
import com.velumtegra.xuimobile.core.runtime.RecoveryAction
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionAuthority
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionResult
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapFailure
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapItem
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapResult
import com.velumtegra.xuimobile.core.runtime.RecoveryExitProvenance
import com.velumtegra.xuimobile.core.runtime.RecoveryRuntimeAdmission

/**
 * Exact Android-host bridge into the already-proven Phase 4.4 recovery/admission barriers.
 *
 * This class deliberately performs no Service lifecycle work, no SSH work and no journal write.
 * A visible Android host supplies one exact [OperationId]; the bridge rebuilds recovery plans from
 * durable truth, selects only that exact operation, then asks the process-scoped coordinator for an
 * explicit-user admission. The returned binding is still ephemeral runtime ownership, never durable
 * operation truth.
 *
 * Keeping this bridge separate from Service coroutine/lifecycle handling lets the next slice prove
 * cancellation and late-admission cleanup without weakening the coordinator contract here.
 */
internal class ExactOperationHostRuntimeAdmissionBridge(
    private val runtimePort: ExactOperationHostRuntimePort,
    private val previousExitProvenance: () -> RecoveryExitProvenance,
) {
    constructor(
        coordinator: OperationRuntimeCoordinator,
        previousExitProvenance: () -> RecoveryExitProvenance,
    ) : this(
        runtimePort = CoordinatorExactOperationHostRuntimePort(coordinator),
        previousExitProvenance = previousExitProvenance,
    )

    suspend fun bind(operationId: OperationId): ExactOperationHostRuntimeBindResult {
        if (operationId.value.isBlank()) {
            return ExactOperationHostRuntimeBindResult.InvalidOperationId
        }

        val items = when (val bootstrap = runtimePort.bootstrap(previousExitProvenance())) {
            is RecoveryBootstrapResult.Success -> bootstrap.items
            is RecoveryBootstrapResult.Failed -> {
                return ExactOperationHostRuntimeBindResult.BootstrapFailed(bootstrap.failure)
            }
        }

        val matchingItems = items.filter { it.operationId == operationId }
        if (matchingItems.isEmpty()) {
            return ExactOperationHostRuntimeBindResult.OperationNotNonTerminal(operationId)
        }
        if (matchingItems.size != 1) {
            return ExactOperationHostRuntimeBindResult.ContractViolation(
                "Recovery bootstrap returned duplicate exact OperationId entries",
            )
        }

        return when (val item = matchingItems.single()) {
            is RecoveryBootstrapItem.Unavailable -> {
                ExactOperationHostRuntimeBindResult.DurableEvidenceUnavailable(item.failure)
            }

            is RecoveryBootstrapItem.Planned -> admitExact(item.plan)
        }
    }

    fun release(binding: ExactOperationHostRuntimeBinding): OperationRuntimeReleaseResult =
        runtimePort.release(binding.token)

    private suspend fun admitExact(plan: ColdStartRecoveryPlan): ExactOperationHostRuntimeBindResult =
        when (
            val admission = runtimePort.admit(
                plan = plan,
                authority = RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED,
            )
        ) {
            is ExactOperationHostPortAdmissionResult.Admitted -> {
                ExactOperationHostRuntimeBindResult.Bound(
                    ExactOperationHostRuntimeBinding(
                        operationId = plan.operationId,
                        token = admission.token,
                    ),
                )
            }

            ExactOperationHostPortAdmissionResult.RequiresExplicitAuthorization -> {
                ExactOperationHostRuntimeBindResult.ContractViolation(
                    "Explicit-user host admission unexpectedly required additional authorization",
                )
            }

            is ExactOperationHostPortAdmissionResult.NotExecutable -> {
                ExactOperationHostRuntimeBindResult.NotExecutable(admission.action)
            }

            ExactOperationHostPortAdmissionResult.AlreadyOwned -> {
                ExactOperationHostRuntimeBindResult.AlreadyOwned
            }

            is ExactOperationHostPortAdmissionResult.StalePlan -> {
                ExactOperationHostRuntimeBindResult.StalePlan(
                    operationId = admission.operationId,
                    expectedRevision = admission.expectedRevision,
                    actualRevision = admission.actualRevision,
                )
            }

            is ExactOperationHostPortAdmissionResult.Failed -> {
                ExactOperationHostRuntimeBindResult.AdmissionFailed(admission.failure)
            }
        }
}

internal data class ExactOperationHostRuntimeBinding(
    val operationId: OperationId,
    internal val token: ExactOperationHostRuntimeToken,
)

internal sealed interface ExactOperationHostRuntimeBindResult {
    data class Bound(val binding: ExactOperationHostRuntimeBinding) : ExactOperationHostRuntimeBindResult

    data object InvalidOperationId : ExactOperationHostRuntimeBindResult

    /** Exact OperationId was not present in the durable nonterminal recovery set. */
    data class OperationNotNonTerminal(val operationId: OperationId) : ExactOperationHostRuntimeBindResult

    /** The exact operation exists, but its durable history could not be safely read. */
    data class DurableEvidenceUnavailable(
        val failure: RecoveryBootstrapFailure,
    ) : ExactOperationHostRuntimeBindResult

    /** The whole recovery bootstrap could not be trusted/read safely enough to select an operation. */
    data class BootstrapFailed(
        val failure: RecoveryBootstrapFailure,
    ) : ExactOperationHostRuntimeBindResult

    data class NotExecutable(val action: RecoveryAction) : ExactOperationHostRuntimeBindResult

    data object AlreadyOwned : ExactOperationHostRuntimeBindResult

    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExactOperationHostRuntimeBindResult

    data class AdmissionFailed(
        val failure: RecoveryBootstrapFailure,
    ) : ExactOperationHostRuntimeBindResult

    data class ContractViolation(val reason: String) : ExactOperationHostRuntimeBindResult
}

/** Opaque process-local admission identity; Android host code cannot invent/rebind durable truth. */
internal interface ExactOperationHostRuntimeToken

internal interface ExactOperationHostRuntimePort {
    suspend fun bootstrap(exitProvenance: RecoveryExitProvenance): RecoveryBootstrapResult

    suspend fun admit(
        plan: ColdStartRecoveryPlan,
        authority: RecoveryAdmissionAuthority,
    ): ExactOperationHostPortAdmissionResult

    fun release(token: ExactOperationHostRuntimeToken): OperationRuntimeReleaseResult
}

internal sealed interface ExactOperationHostPortAdmissionResult {
    data class Admitted(val token: ExactOperationHostRuntimeToken) : ExactOperationHostPortAdmissionResult
    data object RequiresExplicitAuthorization : ExactOperationHostPortAdmissionResult
    data class NotExecutable(val action: RecoveryAction) : ExactOperationHostPortAdmissionResult
    data object AlreadyOwned : ExactOperationHostPortAdmissionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : ExactOperationHostPortAdmissionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : ExactOperationHostPortAdmissionResult
}

internal data class CoordinatorAdmissionToken(
    val admission: RecoveryRuntimeAdmission,
) : ExactOperationHostRuntimeToken

private class CoordinatorExactOperationHostRuntimePort(
    private val coordinator: OperationRuntimeCoordinator,
) : ExactOperationHostRuntimePort {
    override suspend fun bootstrap(exitProvenance: RecoveryExitProvenance): RecoveryBootstrapResult =
        coordinator.bootstrapRecovery(exitProvenance)

    override suspend fun admit(
        plan: ColdStartRecoveryPlan,
        authority: RecoveryAdmissionAuthority,
    ): ExactOperationHostPortAdmissionResult = when (
        val result = coordinator.admitRecovery(plan, authority)
    ) {
        is RecoveryAdmissionResult.Admitted -> ExactOperationHostPortAdmissionResult.Admitted(
            CoordinatorAdmissionToken(result.admission),
        )

        RecoveryAdmissionResult.RequiresExplicitAuthorization ->
            ExactOperationHostPortAdmissionResult.RequiresExplicitAuthorization

        is RecoveryAdmissionResult.NotExecutable ->
            ExactOperationHostPortAdmissionResult.NotExecutable(result.action)

        RecoveryAdmissionResult.AlreadyOwned -> ExactOperationHostPortAdmissionResult.AlreadyOwned

        is RecoveryAdmissionResult.StalePlan -> ExactOperationHostPortAdmissionResult.StalePlan(
            operationId = result.operationId,
            expectedRevision = result.expectedRevision,
            actualRevision = result.actualRevision,
        )

        is RecoveryAdmissionResult.Failed -> ExactOperationHostPortAdmissionResult.Failed(result.failure)
    }

    override fun release(token: ExactOperationHostRuntimeToken): OperationRuntimeReleaseResult {
        require(token is CoordinatorAdmissionToken) { "Runtime token did not originate from coordinator port" }
        return coordinator.release(token.admission)
    }
}

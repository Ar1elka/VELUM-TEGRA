package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.FreshInstallAuthorizationPolicy
import com.velumtegra.xuimobile.core.domain.FreshInstallVerificationResult
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.ReviewedInstallPlanPolicy
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.FreshInstallConflictState
import com.velumtegra.xuimobile.core.model.FreshInstallPreflightProof
import com.velumtegra.xuimobile.core.model.FreshInstallScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.FreshInstallReadinessObservationResult
import com.velumtegra.xuimobile.core.ssh.FreshInstallReadinessSshAdapter
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.InstallerSshExecutionResult
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Instant

/** Production adapter boundary kept injectable for focused runtime policy tests. */
internal fun interface InstallerMutationExecutionPort {
    suspend fun execute(
        plan: com.velumtegra.xuimobile.core.model.ReviewedInstallPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): InstallerSshExecutionResult
}

/**
 * Explicit-consent route only: CAS to MUTATION_IN_FLIGHT, short SSH commands that start a detached
 * server worker, then POST_VERIFY_REQUIRED. Distinct from the synchronous [InstallerMutationExecutionPort].
 */
internal fun interface InstallerDetachedLaunchPort {
    suspend fun launch(
        plan: com.velumtegra.xuimobile.core.model.ReviewedInstallPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): InstallerSshExecutionResult
}

/** Current complete ServerAccess for the explicit-consent route; null (unknown/missing) fails closed. */
internal fun interface InstallerFreshAccessPort {
    suspend fun current(id: ServerAccessId): ServerAccess?
}

/** Read-only fresh-install readiness observation over the same exact session. */
internal fun interface InstallerFreshReadinessPort {
    suspend fun observe(scope: FreshInstallScope, session: SshSessionHandle): FreshInstallReadinessObservationResult
}

/** Read-only post-install/publication boundary, including local COMMIT_VERIFIED completion. */
internal interface InstallerPostInstallRuntimePort {
    suspend fun reconcileAndPublish(
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): InstallerPostInstallCoordinatorResult

    suspend fun finishCommitted(
        current: VersionedOperationSnapshot,
    ): InstallerPostInstallCoordinatorResult
}

/**
 * Phase 8.7 runtime/recovery integration for the acceptance-proven Installer protocol.
 *
 * This coordinator adds no reconnect loop and no second runtime owner. It consumes the already
 * admitted Phase 4 [RecoveryRuntimeAdmission] and the already-published exact operation-owned SSH
 * session. Fresh mutation additionally requires a short-lived [InstallerRuntimeEntryRegistry]
 * authority plus both the durable same-server barrier and process-local mutation lease.
 *
 * Recovery law is deliberately asymmetric:
 * - MUTATION_NOT_STARTED may execute only with live process-local fresh-install authority;
 * - MUTATION_IN_FLIGHT is converted locally to POST_VERIFY_REQUIRED and may only reconcile read-only;
 * - POST_VERIFY_REQUIRED may only reconcile read-only;
 * - COMMIT_VERIFIED terminalizes locally without SSH;
 * - no unsafe durable checkpoint can ever re-enter the mutation executor.
 */
class InstallerRuntimeCoordinator internal constructor(
    private val journal: OperationJournal,
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val sessionRegistry: ExactSessionRegistry,
    private val serverMutationRegistry: ServerMutationLeaseRegistry,
    private val entryRegistry: InstallerRuntimeEntryRegistry,
    private val mutationExecutor: InstallerMutationExecutionPort,
    private val postInstall: InstallerPostInstallRuntimePort,
    private val now: () -> Instant = Instant::now,
    private val consentRegistry: InstallerExplicitConsentRegistry = InstallerExplicitConsentRegistry(),
    private val detachedLaunch: InstallerDetachedLaunchPort? = null,
    private val accessPort: InstallerFreshAccessPort = InstallerFreshAccessPort { null },
    private val readinessPort: InstallerFreshReadinessPort = FreshInstallReadinessSshAdapter().let { adapter ->
        InstallerFreshReadinessPort { scope, session -> adapter.observe(scope, session) }
    },
) {
    /** Explicit, one-shot, process-local install consent (new route; the legacy proof route is unchanged). */
    fun registerExplicitInstallConsent(
        consent: InstallerExplicitInstallConsent,
    ): InstallerExplicitConsentRegistrationResult = consentRegistry.register(consent, now())

    fun discardExplicitInstallConsent(operationId: OperationId): Boolean = consentRegistry.discard(operationId)

    fun registerFreshAuthorization(
        target: com.velumtegra.xuimobile.core.domain.VerifiedFreshInstallTarget,
    ): InstallerRuntimeEntryRegistrationResult = entryRegistry.register(target)

    fun discardFreshAuthorization(operationId: OperationId): Boolean = entryRegistry.discard(operationId)

    /**
     * Local-only decision performed before Phase 4 opens SSH.
     * COMMIT_VERIFIED is completed here so crash recovery never reconnects merely to terminalize.
     */
    suspend fun prepareTransport(
        admission: RecoveryRuntimeAdmission,
    ): InstallerRuntimePreparationResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return InstallerRuntimePreparationResult.AdmissionLost
        }
        val current = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result.toPreparationResult()
        }
        if (current.snapshot.type != OperationType.INSTALL) {
            return InstallerRuntimePreparationResult.NotInstallerOperation
        }
        val target = current.snapshot.target as? OperationTarget.ServerTarget
            ?: return InstallerRuntimePreparationResult.ContractViolation(
                "INSTALL runtime requires exact ServerTarget",
            )

        if (current.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            // Any checkpoint at/after the dispatch boundary makes pre-dispatch authority obsolete.
            // Discard it eagerly so a forged/stale process-local entry cannot linger across read-only
            // reconciliation or local commit completion.
            entryRegistry.discard(current.snapshot.operationId)
            consentRegistry.discard(current.snapshot.operationId)
        }

        return when (current.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> when (
                val entry = entryRegistry.inspect(current, now())
            ) {
                InstallerRuntimeEntryInspection.Available -> InstallerRuntimePreparationResult.TransportRequired
                InstallerRuntimeEntryInspection.Missing -> when (
                    val consent = consentRegistry.inspect(current, now())
                ) {
                    InstallerRuntimeEntryInspection.Available -> InstallerRuntimePreparationResult.TransportRequired
                    InstallerRuntimeEntryInspection.Missing -> InstallerRuntimePreparationResult.FreshAuthorizationRequired
                    InstallerRuntimeEntryInspection.Expired -> {
                        consentRegistry.discard(current.snapshot.operationId)
                        InstallerRuntimePreparationResult.FreshAuthorizationExpired
                    }
                    is InstallerRuntimeEntryInspection.ContractViolation -> {
                        consentRegistry.discard(current.snapshot.operationId)
                        InstallerRuntimePreparationResult.ContractViolation(consent.reason)
                    }
                }
                InstallerRuntimeEntryInspection.Expired -> {
                    entryRegistry.discard(current.snapshot.operationId)
                    InstallerRuntimePreparationResult.FreshAuthorizationExpired
                }
                is InstallerRuntimeEntryInspection.ContractViolation -> {
                    InstallerRuntimePreparationResult.ContractViolation(entry.reason)
                }
            }

            CheckpointSemantics.MUTATION_IN_FLIGHT,
            CheckpointSemantics.POST_VERIFY_REQUIRED,
            -> InstallerRuntimePreparationResult.TransportRequired

            CheckpointSemantics.COMMIT_VERIFIED -> {
                InstallerRuntimePreparationResult.Completed(postInstall.finishCommitted(current))
            }

            CheckpointSemantics.TERMINAL -> InstallerRuntimePreparationResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL Installer checkpoint",
            )

            else -> InstallerRuntimePreparationResult.ContractViolation(
                "Installer durable checkpoint ${current.snapshot.checkpoint.semantics} is not an approved runtime entry boundary for ${target.serverId.value}",
            )
        }
    }

    /** Consume one connected exact session without creating/retrying transport here. */
    suspend fun execute(
        admission: RecoveryRuntimeAdmission,
        sessionBinding: SessionBinding,
    ): InstallerRuntimeExecutionResult {
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return InstallerRuntimeExecutionResult.AdmissionLost
        }
        validateCallerBinding(admission, sessionBinding)?.let { return it }
        val session = when (val current = currentSession(admission, sessionBinding)) {
            is CurrentSession.Handle -> current.handle
            is CurrentSession.Result -> return current.result
        }
        val before = when (val read = readCurrent(admission)) {
            is CurrentRead.Current -> read.value
            is CurrentRead.Result -> return read.result
        }
        if (before.snapshot.type != OperationType.INSTALL) {
            return InstallerRuntimeExecutionResult.NotInstallerOperation
        }
        val target = before.snapshot.target as? OperationTarget.ServerTarget
            ?: return InstallerRuntimeExecutionResult.ContractViolation(
                "INSTALL runtime requires exact ServerTarget",
            )

        return when (before.snapshot.checkpoint.semantics) {
            CheckpointSemantics.MUTATION_NOT_STARTED -> executeFreshMutation(
                admission = admission,
                current = before,
                target = target,
                session = session,
            )

            CheckpointSemantics.MUTATION_IN_FLIGHT -> {
                val postVerify = when (val promoted = promoteUnsafeToPostVerify(before)) {
                    is PromoteResult.Promoted -> promoted.current
                    is PromoteResult.Result -> return promoted.result
                }
                InstallerRuntimeExecutionResult.PostInstall(
                    postInstall.reconcileAndPublish(postVerify, session),
                )
            }

            CheckpointSemantics.POST_VERIFY_REQUIRED -> InstallerRuntimeExecutionResult.PostInstall(
                postInstall.reconcileAndPublish(before, session),
            )

            CheckpointSemantics.COMMIT_VERIFIED -> InstallerRuntimeExecutionResult.PostInstall(
                postInstall.finishCommitted(before),
            )

            CheckpointSemantics.TERMINAL -> InstallerRuntimeExecutionResult.ContractViolation(
                "Nonterminal runtime admission points at TERMINAL Installer checkpoint",
            )

            else -> InstallerRuntimeExecutionResult.ContractViolation(
                "Installer durable checkpoint ${before.snapshot.checkpoint.semantics} is outside the Phase 8.7 runtime contract",
            )
        }
    }

    private suspend fun executeFreshMutation(
        admission: RecoveryRuntimeAdmission,
        current: VersionedOperationSnapshot,
        target: OperationTarget.ServerTarget,
        session: SshSessionHandle,
    ): InstallerRuntimeExecutionResult {
        val lease = when (val acquired = serverMutationRegistry.tryAcquire(target.serverId, current.snapshot.operationId)) {
            is ServerMutationAcquireResult.Acquired -> acquired.lease
            ServerMutationAcquireResult.AlreadyOwned -> {
                return InstallerRuntimeExecutionResult.ServerMutationAlreadyOwned
            }
        }

        try {
            val durable = when (val list = journal.listNonTerminal()) {
                is OperationJournalResult.Success -> list.value
                is OperationJournalResult.Corruption -> {
                    return InstallerRuntimeExecutionResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                            list.reason,
                        ),
                    )
                }
                is OperationJournalResult.StorageFailure -> {
                    return InstallerRuntimeExecutionResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                            list.reason,
                        ),
                    )
                }
                else -> {
                    return InstallerRuntimeExecutionResult.Failed(
                        contractFailure("Installer listNonTerminal returned ${list::class.simpleName}"),
                    )
                }
            }
            when (
                val barrier = DurableServerMutationBarrierPolicy.evaluate(
                    serverId = target.serverId,
                    durableOperations = durable.map { it.snapshot },
                )
            ) {
                ServerMutationBarrierDecision.Allowed -> Unit
                is ServerMutationBarrierDecision.BlockedByUncertainMutation -> {
                    return InstallerRuntimeExecutionResult.BlockedByDurableMutation(barrier.blockers)
                }
            }

            // Re-read after taking the process lease and durable barrier evidence. Any revision move
            // means the caller must re-plan; fresh authority is not consumed for a stale admission.
            val latest = when (val read = readCurrent(admission)) {
                is CurrentRead.Current -> read.value
                is CurrentRead.Result -> return read.result
            }
            if (latest.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
                return InstallerRuntimeExecutionResult.ContractViolation(
                    "Fresh Installer mutation lost its MUTATION_NOT_STARTED boundary before dispatch",
                )
            }

            // Legacy verified-proof authority keeps its exact behaviour; otherwise the new explicit-consent
            // route applies, which re-observes the target read-only on this same session first.
            if (entryRegistry.inspect(latest, now()) == InstallerRuntimeEntryInspection.Missing) {
                return executeWithExplicitConsent(admission, latest, target, session, lease)
            }
            val verifiedTarget = when (val entry = entryRegistry.consume(latest, now())) {
                is InstallerRuntimeEntryConsumeResult.Consumed -> entry.target
                InstallerRuntimeEntryConsumeResult.Missing -> {
                    return InstallerRuntimeExecutionResult.FreshAuthorizationRequired
                }
                InstallerRuntimeEntryConsumeResult.Expired -> {
                    return InstallerRuntimeExecutionResult.FreshAuthorizationExpired
                }
                is InstallerRuntimeEntryConsumeResult.ContractViolation -> {
                    return InstallerRuntimeExecutionResult.ContractViolation(entry.reason)
                }
            }
            val plan = runCatching { ReviewedInstallPlanPolicy.build(verifiedTarget) }
                .getOrElse {
                    return InstallerRuntimeExecutionResult.ContractViolation(
                        "Verified fresh-install authority could not build the canonical reviewed plan",
                    )
                }

            val executed = mutationExecutor.execute(plan, latest, session)
            return when (executed) {
                is InstallerSshExecutionResult.AwaitingVerification -> InstallerRuntimeExecutionResult.PostInstall(
                    postInstall.reconcileAndPublish(executed.durable, session),
                )
                else -> InstallerRuntimeExecutionResult.MutationExecution(executed)
            }
        } finally {
            serverMutationRegistry.release(lease)
        }
    }

    /**
     * Explicit-consent route, called under the server mutation lease after the durable barrier. The
     * consent is consumed first (one-shot, never restored). Every refusal below happens before any
     * durable checkpoint or remote write, so it is reported as [InstallerRuntimeExecutionResult.FreshInstallRefused],
     * never as an uncertain mutation. Only a read-only Ready with the exact scope may become a proof.
     */
    private suspend fun executeWithExplicitConsent(
        admission: RecoveryRuntimeAdmission,
        latest: VersionedOperationSnapshot,
        target: OperationTarget.ServerTarget,
        session: SshSessionHandle,
        lease: ServerMutationLease,
    ): InstallerRuntimeExecutionResult {
        val consent = when (val consumed = consentRegistry.consume(latest, now())) {
            is InstallerExplicitConsentConsumeResult.Consumed -> consumed.consent
            InstallerExplicitConsentConsumeResult.Missing -> return InstallerRuntimeExecutionResult.FreshAuthorizationRequired
            InstallerExplicitConsentConsumeResult.Expired -> return InstallerRuntimeExecutionResult.FreshAuthorizationExpired
            is InstallerExplicitConsentConsumeResult.ContractViolation -> {
                return InstallerRuntimeExecutionResult.ContractViolation(consumed.reason)
            }
        }
        fun refused(reason: FreshInstallRefusalReason, readiness: FreshInstallReadinessObservationResult? = null) =
            InstallerRuntimeExecutionResult.FreshInstallRefused(reason, readiness)

        val binding = session.binding
        recheckBeforeWrite(admission, lease, consent, session, binding, latest)?.let { return refused(it) }

        val scope = FreshInstallScope(latest.snapshot.operationId, target.serverId, target.serverAccessId)
        val observed = readinessPort.observe(scope, session)
        // The read-only observation suspended: re-validate everything, including the short TTL.
        recheckBeforeWrite(admission, lease, consent, session, binding, latest)?.let { return refused(it, observed) }
        val facts = (observed as? FreshInstallReadinessObservationResult.Ready)?.facts
            ?: return refused(FreshInstallRefusalReason.READINESS_NOT_READY, observed)
        if (facts.scope != scope) return refused(FreshInstallRefusalReason.READINESS_SCOPE_MISMATCH, observed)

        val at = now()
        if (facts.observedAt.isBefore(consent.grantedAt) || facts.observedAt.isAfter(at) || at.isAfter(consent.validUntil)) {
            return refused(FreshInstallRefusalReason.AUTHORIZATION_REJECTED, observed)
        }
        val proof = FreshInstallPreflightProof(
            id = TargetProofId("explicit-install-consent-${scope.operationId.value}"),
            scope = scope,
            platform = facts.platform,
            installerCapability = facts.installerCapability,
            privilegeCapability = facts.privilegeCapability,
            conflictState = FreshInstallConflictState.PROVEN_CLEAR,
            observedAt = facts.observedAt,
            validUntil = consent.validUntil,
        )
        val verified = when (val v = FreshInstallAuthorizationPolicy.verify(latest.snapshot, proof, at)) {
            is FreshInstallVerificationResult.Verified -> v.target
            is FreshInstallVerificationResult.Rejected -> {
                return refused(FreshInstallRefusalReason.AUTHORIZATION_REJECTED, observed)
            }
        }
        val plan = runCatching { ReviewedInstallPlanPolicy.build(verified) }
            .getOrElse { return refused(FreshInstallRefusalReason.PLAN_REJECTED, observed) }

        // No detached launcher in this composition: refuse before any checkpoint rather than fall back
        // to the long synchronous executor that this route exists to avoid.
        val launcher = detachedLaunch ?: return refused(FreshInstallRefusalReason.DETACHED_LAUNCH_UNAVAILABLE, observed)
        return when (val launched = launcher.launch(plan, latest, session)) {
            // Hand-off confirmed and POST_VERIFY_REQUIRED recorded: do not wait here; completion is observed
            // later by read-only reconciliation through the normal recovery admission.
            is InstallerSshExecutionResult.DetachedWorkerLaunched ->
                InstallerRuntimeExecutionResult.DetachedWorkerLaunched(launched.durable)
            else -> InstallerRuntimeExecutionResult.MutationExecution(launched)
        }
    }

    /** Live lease/record/session/access/pin/TTL checks; null means everything still matches exactly. */
    private suspend fun recheckBeforeWrite(
        admission: RecoveryRuntimeAdmission,
        lease: ServerMutationLease,
        consent: InstallerExplicitInstallConsent,
        session: SshSessionHandle,
        binding: SessionBinding,
        latest: VersionedOperationSnapshot,
    ): FreshInstallRefusalReason? {
        val access = accessPort.current(consent.access.id) ?: return FreshInstallRefusalReason.ACCESS_UNAVAILABLE
        if (access != consent.access) return FreshInstallRefusalReason.ACCESS_CHANGED
        val journal = readCurrent(admission) as? CurrentRead.Current ?: return FreshInstallRefusalReason.JOURNAL_CHANGED
        if (journal.value != latest || journal.value.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return FreshInstallRefusalReason.JOURNAL_CHANGED
        }
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) return FreshInstallRefusalReason.ADMISSION_LOST
        if (!serverMutationRegistry.isCurrent(lease)) return FreshInstallRefusalReason.MUTATION_LEASE_LOST
        val at = now()
        if (at.isBefore(consent.grantedAt) || at.isAfter(consent.validUntil)) {
            return FreshInstallRefusalReason.CONSENT_EXPIRED
        }
        val live = sessionRegistry.find(
            SessionOwner.Operation(consent.operationId),
            consent.access.id,
        )
        if (live !== session || !session.isOpen || session.binding != binding) {
            return FreshInstallRefusalReason.SESSION_CHANGED
        }
        val expectedPin = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey) as? HostKeyFingerprintParseResult.Valid)
            ?.fingerprint?.asHexSha256()
        val presentedPin = (session as? VerifiedHostKeySshSessionHandle)?.verifiedHostKeySha256
        if (expectedPin == null || presentedPin == null ||
            !MessageDigest.isEqual(expectedPin.encodeToByteArray(), presentedPin.encodeToByteArray())
        ) {
            return FreshInstallRefusalReason.SESSION_PIN_UNVERIFIED
        }
        return null
    }

    /**
     * Process death or transport loss after mutation dispatch is never a retry permission. We make
     * the durable state more conservative before any read-only post-install observation.
     */
    private suspend fun promoteUnsafeToPostVerify(
        current: VersionedOperationSnapshot,
    ): PromoteResult {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) {
            return PromoteResult.Result(
                InstallerRuntimeExecutionResult.ContractViolation(
                    "Installer runtime clock moved before durable operation time",
                ),
            )
        }
        val next = current.snapshot.copy(
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint(
                phaseName = "INSTALLER_RUNTIME_RECONCILIATION_REQUIRED",
                semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (
            val advanced = journal.advance(current.snapshot.operationId, current.revision, next)
        ) {
            is OperationJournalResult.Success -> PromoteResult.Promoted(advanced.value)
            is OperationJournalResult.StaleRevision -> PromoteResult.Result(
                InstallerRuntimeExecutionResult.StalePlan(
                    current.snapshot.operationId,
                    advanced.expected,
                    advanced.actual,
                ),
            )
            is OperationJournalResult.Corruption -> PromoteResult.Result(
                InstallerRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        advanced.reason,
                    ),
                ),
            )
            is OperationJournalResult.StorageFailure -> PromoteResult.Result(
                InstallerRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                        advanced.reason,
                    ),
                ),
            )
            is OperationJournalResult.InvalidTransition -> PromoteResult.Result(
                InstallerRuntimeExecutionResult.Failed(
                    contractFailure("Installer unsafe recovery advance rejected: ${advanced.reason}"),
                ),
            )
            else -> PromoteResult.Result(
                InstallerRuntimeExecutionResult.Failed(
                    contractFailure("Installer unsafe recovery advance returned ${advanced::class.simpleName}"),
                ),
            )
        }
    }

    private fun validateCallerBinding(
        admission: RecoveryRuntimeAdmission,
        binding: SessionBinding,
    ): InstallerRuntimeExecutionResult.ContractViolation? {
        if (binding.owner != SessionOwner.Operation(admission.plan.operationId)) {
            return InstallerRuntimeExecutionResult.ContractViolation(
                "Installer session belongs to a different OperationId",
            )
        }
        if (binding.serverAccessId != admission.plan.target.serverAccessId) {
            return InstallerRuntimeExecutionResult.ContractViolation(
                "Installer session uses a different ServerAccessId than the durable target",
            )
        }
        return null
    }

    private fun currentSession(
        admission: RecoveryRuntimeAdmission,
        expected: SessionBinding,
    ): CurrentSession {
        val owner = SessionOwner.Operation(admission.plan.operationId)
        val current = sessionRegistry.find(owner, admission.plan.target.serverAccessId)
            ?: return CurrentSession.Result(InstallerRuntimeExecutionResult.SessionUnavailable)
        if (current.binding.sessionId != expected.sessionId) {
            return CurrentSession.Result(
                InstallerRuntimeExecutionResult.StaleSession(expected.sessionId, current.binding.sessionId),
            )
        }
        if (current.binding != expected) {
            return CurrentSession.Result(
                InstallerRuntimeExecutionResult.ContractViolation(
                    "Live Installer session binding changed exact owner/access identity",
                ),
            )
        }
        return CurrentSession.Handle(current)
    }

    private suspend fun readCurrent(admission: RecoveryRuntimeAdmission): CurrentRead {
        val current = when (val result = journal.get(admission.plan.operationId)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.NotFound -> {
                return CurrentRead.Result(
                    InstallerRuntimeExecutionResult.Failed(
                        contractFailure("Installer operation no longer exists"),
                    ),
                )
            }
            is OperationJournalResult.Corruption -> {
                return CurrentRead.Result(
                    InstallerRuntimeExecutionResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                            result.reason,
                        ),
                    ),
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return CurrentRead.Result(
                    InstallerRuntimeExecutionResult.Failed(
                        RecoveryBootstrapFailure(
                            RecoveryBootstrapFailureKind.JOURNAL_STORAGE_FAILURE,
                            result.reason,
                        ),
                    ),
                )
            }
            else -> {
                return CurrentRead.Result(
                    InstallerRuntimeExecutionResult.Failed(
                        contractFailure("Installer exact journal read returned ${result::class.simpleName}"),
                    ),
                )
            }
        }
        if (current.snapshot.operationId != admission.plan.operationId ||
            current.snapshot.target != admission.plan.target
        ) {
            return CurrentRead.Result(
                InstallerRuntimeExecutionResult.Failed(
                    RecoveryBootstrapFailure(
                        RecoveryBootstrapFailureKind.JOURNAL_CORRUPTION,
                        "Installer operation identity/target changed after runtime admission",
                    ),
                ),
            )
        }
        if (current.revision != admission.plan.expectedRevision) {
            return CurrentRead.Result(
                InstallerRuntimeExecutionResult.StalePlan(
                    admission.plan.operationId,
                    admission.plan.expectedRevision,
                    current.revision,
                ),
            )
        }
        if (current.snapshot.status in TERMINAL_STATUSES ||
            current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
        ) {
            return CurrentRead.Result(
                InstallerRuntimeExecutionResult.Failed(
                    contractFailure("Installer admission points at terminal durable state"),
                ),
            )
        }
        return CurrentRead.Current(current)
    }

    private fun contractFailure(reason: String): RecoveryBootstrapFailure = RecoveryBootstrapFailure(
        RecoveryBootstrapFailureKind.JOURNAL_CONTRACT_VIOLATION,
        reason,
    )

    private sealed interface PromoteResult {
        data class Promoted(val current: VersionedOperationSnapshot) : PromoteResult
        data class Result(val result: InstallerRuntimeExecutionResult) : PromoteResult
    }

    private sealed interface CurrentRead {
        data class Current(val value: VersionedOperationSnapshot) : CurrentRead
        data class Result(val result: InstallerRuntimeExecutionResult) : CurrentRead
    }

    private sealed interface CurrentSession {
        data class Handle(val handle: SshSessionHandle) : CurrentSession
        data class Result(val result: InstallerRuntimeExecutionResult) : CurrentSession
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}

sealed interface InstallerRuntimePreparationResult {
    /** Not an INSTALL operation; the existing read-only consumers may continue. */
    data object NotInstallerOperation : InstallerRuntimePreparationResult

    /** Exact SSH transport is required for fresh mutation or read-only reconciliation. */
    data object TransportRequired : InstallerRuntimePreparationResult

    /** MUTATION_NOT_STARTED exists but process-local fresh proof/authority is absent. */
    data object FreshAuthorizationRequired : InstallerRuntimePreparationResult
    data object FreshAuthorizationExpired : InstallerRuntimePreparationResult

    /** COMMIT_VERIFIED completed locally without opening SSH. */
    data class Completed(val result: InstallerPostInstallCoordinatorResult) : InstallerRuntimePreparationResult

    data object AdmissionLost : InstallerRuntimePreparationResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : InstallerRuntimePreparationResult
    data class Failed(val failure: RecoveryBootstrapFailure) : InstallerRuntimePreparationResult
    data class ContractViolation(val reason: String) : InstallerRuntimePreparationResult
}

sealed interface InstallerRuntimeExecutionResult {
    data object NotInstallerOperation : InstallerRuntimeExecutionResult
    data object AdmissionLost : InstallerRuntimeExecutionResult
    data object SessionUnavailable : InstallerRuntimeExecutionResult
    data class StaleSession(
        val expectedSessionId: SessionId,
        val actualSessionId: SessionId?,
    ) : InstallerRuntimeExecutionResult
    data object FreshAuthorizationRequired : InstallerRuntimeExecutionResult
    data object FreshAuthorizationExpired : InstallerRuntimeExecutionResult
    data object ServerMutationAlreadyOwned : InstallerRuntimeExecutionResult

    /** Explicit-consent route refused before any checkpoint or write; consent is spent. Not a mutation. */
    data class FreshInstallRefused(
        val reason: FreshInstallRefusalReason,
        val readiness: FreshInstallReadinessObservationResult? = null,
    ) : InstallerRuntimeExecutionResult
    data class BlockedByDurableMutation(
        val blockers: List<UncertainMutationBlocker>,
    ) : InstallerRuntimeExecutionResult
    data class MutationExecution(val result: InstallerSshExecutionResult) : InstallerRuntimeExecutionResult

    /** Explicit-consent route: detached worker handed off; durable POST_VERIFY_REQUIRED; nothing awaited. */
    data class DetachedWorkerLaunched(val durable: VersionedOperationSnapshot) : InstallerRuntimeExecutionResult
    data class PostInstall(val result: InstallerPostInstallCoordinatorResult) : InstallerRuntimeExecutionResult
    data class StalePlan(
        val operationId: OperationId,
        val expectedRevision: OperationRevision,
        val actualRevision: OperationRevision,
    ) : InstallerRuntimeExecutionResult
    data class Failed(val failure: RecoveryBootstrapFailure) : InstallerRuntimeExecutionResult
    data class ContractViolation(val reason: String) : InstallerRuntimeExecutionResult
}

enum class FreshInstallRefusalReason {
    ADMISSION_LOST,
    MUTATION_LEASE_LOST,
    CONSENT_EXPIRED,
    SESSION_CHANGED,
    SESSION_PIN_UNVERIFIED,
    ACCESS_UNAVAILABLE,
    ACCESS_CHANGED,
    JOURNAL_CHANGED,
    READINESS_NOT_READY,
    READINESS_SCOPE_MISMATCH,
    AUTHORIZATION_REJECTED,
    PLAN_REJECTED,
    DETACHED_LAUNCH_UNAVAILABLE,
}

private fun InstallerRuntimeExecutionResult.toPreparationResult(): InstallerRuntimePreparationResult = when (this) {
    InstallerRuntimeExecutionResult.NotInstallerOperation -> InstallerRuntimePreparationResult.NotInstallerOperation
    InstallerRuntimeExecutionResult.AdmissionLost -> InstallerRuntimePreparationResult.AdmissionLost
    is InstallerRuntimeExecutionResult.StalePlan -> InstallerRuntimePreparationResult.StalePlan(
        operationId,
        expectedRevision,
        actualRevision,
    )
    is InstallerRuntimeExecutionResult.Failed -> InstallerRuntimePreparationResult.Failed(failure)
    is InstallerRuntimeExecutionResult.ContractViolation -> InstallerRuntimePreparationResult.ContractViolation(reason)
    else -> InstallerRuntimePreparationResult.ContractViolation(
        "Unexpected session-dependent Installer result during local preparation: ${this::class.simpleName}",
    )
}

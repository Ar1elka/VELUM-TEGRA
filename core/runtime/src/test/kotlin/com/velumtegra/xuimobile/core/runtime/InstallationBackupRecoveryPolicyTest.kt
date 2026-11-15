package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class InstallationBackupRecoveryPolicyTest {
    private val at = Instant.parse("2026-10-17T01:00:00Z")
    private val server = ServerId("server")
    private fun operation(semantics: CheckpointSemantics, status: OperationStatus = OperationStatus.RUNNING) =
        VersionedOperationSnapshot(OperationSnapshot(OperationId("backup"), OperationType.INSTALLATION_BACKUP,
            OperationTarget.InstallationTarget(server, ServerAccessId("ssh"), XuiInstallationId("install")), status,
            OperationCheckpoint("IBB1_COPYING:AMD64:3.10.0:" + "a".repeat(64), semantics, at), at, at), OperationRevision(1))
    @Test fun noExitProvenanceAutomaticallyReplaysEvenAPendingBackup() {
        RecoveryExitProvenance.values().forEach { exit ->
            val p = ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(operation(CheckpointSemantics.MUTATION_NOT_STARTED),
                OperationDurabilityValidation.Valid, exit))
            assertFalse(p.automaticAllowed); assertEquals(RecoveryAction.RECONNECT_EXACT_OWNER, p.action)
        }
    }
    @Test fun uncertainOrPostVerifyBackupIsAlwaysExplicitReadOnlyReconciliation() {
        listOf(CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED).forEach { semantics ->
            RecoveryExitProvenance.values().forEach { exit ->
                val p = ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(operation(semantics), OperationDurabilityValidation.Valid, exit))
                assertFalse(p.automaticAllowed); assertEquals(RecoveryAction.RECONCILE_READ_ONLY, p.action)
            }
        }
    }
    @Test fun unresolvedBackupBlocksOtherMutationsOnSameServer() {
        val s = operation(CheckpointSemantics.MUTATION_IN_FLIGHT).snapshot
        assertTrue(DurableServerMutationBarrierPolicy.evaluate(server, listOf(s)) is ServerMutationBarrierDecision.BlockedByUncertainMutation)
        assertEquals(ServerMutationBarrierDecision.Allowed, DurableServerMutationBarrierPolicy.evaluate(ServerId("other"), listOf(s)))
    }
    @Test fun verifiedTerminalBackupDoesNotKeepMutationBarrier() {
        val c = operation(CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED)
        assertEquals(ServerMutationBarrierDecision.Allowed, DurableServerMutationBarrierPolicy.evaluate(server, listOf(c.snapshot)))
        val p = ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(c, OperationDurabilityValidation.Valid, RecoveryExitProvenance.PROCESS_DEATH))
        assertEquals(RecoveryAction.NO_ACTION, p.action); assertFalse(p.automaticAllowed)
    }
}

package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionPlan
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsCommitTransactionExecutionUsePort
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitFailureInjection
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitOutcome
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitTransaction
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/** Phase 11.53: exact verified staging receipt -> bounded rename-only commit/rollback transaction. */
internal object SiteProductionDeploymentAndroidRealVpsCommitTransactionExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun commitOrRollbackOnce(
        plan: SiteDeployerCommitTransactionPlan,
        stagingExecutionProof: SiteProductionDeploymentRealVpsStagingWriteExecutionProof,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        failureInjection: SiteRemoteSftpCommitFailureInjection,
        executionUsePort: SiteProductionDeploymentRealVpsCommitTransactionExecutionUsePort,
    ): SiteProductionDeploymentRealVpsCommitTransactionExecutionProof {
        SiteDeployerCommitTransactionBoundary.validate(plan)
        SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary.validateProof(stagingExecutionProof)
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(freshResolutionProof)

        require(stagingExecutionProof.stagingWritePlanSha256 == plan.stagingWritePlanSha256)
        require(stagingExecutionProof.sourceTreeSha256 == plan.sourceTree.treeSha256)
        require(stagingExecutionProof.targetRoot == plan.targetRoot)
        require(stagingExecutionProof.stagingRoot == plan.stagingRoot)
        require(stagingExecutionProof.remoteHostIdentity == plan.remoteHostIdentity)
        require(stagingExecutionProof.serverAccessId == serverAccess.id.value)
        require(stagingExecutionProof.serverAccessBindingSha256 == freshResolutionProof.serverAccessBindingSha256)
        require(stagingExecutionProof.requiresSeparateCommitBoundary)
        require(stagingExecutionProof.remoteTreeVerified && stagingExecutionProof.sessionClosed)
        require(plan.remoteHostIdentity == serverAccess.endpoint.host)
        require(!isLoopbackHost(serverAccess.endpoint.host))
        require(serverAccess.endpoint.port in 1..65535)
        require(canonicalId.matches(executionAttemptId))
        require(executedAtEpochMillis >= freshResolutionProof.resolvedAtEpochMillis)
        require(executedAtEpochMillis <= freshResolutionProof.authorizationExpiresAtEpochMillis)
        require(freshResolutionProof.status == SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.RESOLVED_TO_EPHEMERAL_LEASE)
        require(freshResolutionProof.secretStoreReadPerformed && !freshResolutionProof.credentialLeaseMaterialRead)
        require(!freshResolutionProof.productionNetworkTouched)
        require(freshResolutionProof.requiresLiveRemoteHostKeyVerification)
        require(freshResolutionProof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccess.id.value,
            secretReferenceType,
            serverAccess.auth.secretId.value,
        )
        require(freshResolutionProof.serverAccessId == serverAccess.id.value)
        require(freshResolutionProof.secretReferenceType == secretReferenceType)
        require(freshResolutionProof.secretReferenceSha256 == secretReferenceSha256)
        require(freshCredentialLease.serverAccessId == serverAccess.id.value)
        require(freshCredentialLease.secretReferenceType == secretReferenceType)
        require(freshCredentialLease.secretReferenceSha256 == secretReferenceSha256)
        require(freshCredentialLease.credentialResolutionConsumptionReceiptSha256 == freshResolutionProof.credentialResolutionConsumptionReceiptSha256)
        require(freshCredentialLease.resolvedAtEpochMillis == freshResolutionProof.resolvedAtEpochMillis)
        require(freshCredentialLease.authorizationExpiresAtEpochMillis == freshResolutionProof.authorizationExpiresAtEpochMillis)

        val expectedHostKey = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid -> throw IllegalArgumentException("Phase 11.53 pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        val bindingSha256 = serverAccessBindingSha256(serverAccess, secretReferenceType, secretReferenceSha256, expectedHostKeySha256)
        require(freshResolutionProof.serverAccessBindingSha256 == bindingSha256)

        // Burn before credential material read and before any network/mutation. Never auto-retry this plan.
        require(executionUsePort.consumeOnce(plan.commitTransactionPlanSha256)) {
            "Phase 11.53 commit transaction was already attempted or durable first-use proof failed closed"
        }

        val ownerId = "phase11_53_${plan.commitTransactionPlanSha256.take(24)}"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId("phase11_53_session_${plan.commitTransactionPlanSha256.take(24)}")
        val leaseStore = OneShotLeaseSecretStore(serverAccess.auth.secretId, freshCredentialLease)
        val factory = JschSshConnectionFactory(secretStore = leaseStore, sessionIdFactory = { deterministicSessionId })
        val registry = ExactSessionRegistry()
        var connectedHandle: VerifiedHostKeySshSessionHandle? = null
        try {
            val connectResult = factory.connect(
                access = serverAccess,
                owner = owner,
                config = SshTransportConfig(
                    tcpConnectTimeout = Duration.ofSeconds(8),
                    handshakeAndAuthTimeout = Duration.ofSeconds(12),
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(5),
                    stdoutCaptureLimitBytes = 4096,
                    stderrCaptureLimitBytes = 4096,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Phase 11.53 fresh SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close(); throw IllegalArgumentException("Phase 11.53 missing verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256)
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)

            val evidence = SiteRemoteSftpCommitTransaction().execute(
                session = verified,
                plan = plan,
                failureInjection = failureInjection,
                channelOpenTimeout = Duration.ofSeconds(5),
            )
            require(evidence.channelOpened && evidence.channelClosed)
            require(evidence.sourceTreeSha256 == plan.sourceTree.treeSha256)
            require(evidence.writeFileOperationCount == 0 && evidence.mkdirOperationCount == 0)
            require(evidence.deleteOperationCount == 0 && evidence.chmodOperationCount == 0)
            require(evidence.chownOrChgrpOperationCount == 0 && evidence.remoteCommandDispatchCount == 0)
            require(evidence.finalTargetVerified && evidence.finalBackupVerified)
            if (evidence.outcome == SiteRemoteSftpCommitOutcome.ROLLED_BACK) require(evidence.finalStagingVerified)

            val sessionIdValue = verified.binding.sessionId.value
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0 && !verified.isOpen)
            connectedHandle = null

            val base = SiteProductionDeploymentRealVpsCommitTransactionExecutionProof(
                contractVersion = CONTRACT_VERSION,
                outcome = evidence.outcome,
                failureInjection = failureInjection,
                executionReceiptConsumed = true,
                commitPlanValidated = true,
                stagingExecutionProofValidated = true,
                freshCredentialResolutionProofValidated = true,
                credentialLeaseMaterialConsumed = true,
                productionNetworkTouched = true,
                hostKeyPinVerifiedAgainstRemote = true,
                freshSshSessionAcquisitionExecuted = true,
                sftpChannelOpened = true,
                sftpChannelClosed = true,
                renameOnlyMutationBoundary = true,
                targetToBackupRenamePerformed = evidence.targetToBackupRenamePerformed,
                stagingToTargetRenamePerformed = evidence.stagingToTargetRenamePerformed,
                targetToStagingRollbackRenamePerformed = evidence.targetToStagingRollbackRenamePerformed,
                backupToTargetRollbackRenamePerformed = evidence.backupToTargetRollbackRenamePerformed,
                rollbackPerformed = evidence.rollbackPerformed,
                finalTargetVerified = evidence.finalTargetVerified,
                finalStagingVerified = evidence.finalStagingVerified,
                finalBackupVerified = evidence.finalBackupVerified,
                backupRetainedAfterCommit = evidence.backupRetainedAfterCommit,
                uploadPerformed = false,
                mkdirPerformed = false,
                deletePerformed = false,
                chmodPerformed = false,
                chownOrChgrpPerformed = false,
                remoteCommandDispatched = false,
                coordinatorInvoked = false,
                exposesDeployUiAction = false,
                commitTransactionPlanSha256 = plan.commitTransactionPlanSha256,
                stagingWritePlanSha256 = plan.stagingWritePlanSha256,
                stagingExecutionProofSha256 = stagingExecutionProof.executionProofSha256,
                sourceTreeSha256 = plan.sourceTree.treeSha256,
                previousTargetTreeSha256 = plan.previousTargetTree?.treeSha256,
                freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
                freshCredentialResolutionConsumptionReceiptSha256 = freshResolutionProof.credentialResolutionConsumptionReceiptSha256,
                serverAccessBindingSha256 = bindingSha256,
                serverAccessId = serverAccess.id.value,
                remoteHostIdentity = serverAccess.endpoint.host,
                remotePort = serverAccess.endpoint.port,
                username = serverAccess.username,
                pinnedHostKeySha256 = expectedHostKeySha256,
                secretReferenceType = secretReferenceType,
                secretReferenceSha256 = secretReferenceSha256,
                targetRoot = plan.targetRoot,
                stagingRoot = plan.stagingRoot,
                backupRoot = plan.backupRoot,
                lstatOperationCount = evidence.lstatOperationCount,
                listOperationCount = evidence.listOperationCount,
                readFileOperationCount = evidence.readFileOperationCount,
                renameOperationCount = evidence.renameOperationCount,
                sessionId = sessionIdValue,
                operationOwnerId = ownerId,
                credentialResolvedAtEpochMillis = freshResolutionProof.resolvedAtEpochMillis,
                executedAtEpochMillis = executedAtEpochMillis,
                freshCredentialAuthorizationExpiresAtEpochMillis = freshResolutionProof.authorizationExpiresAtEpochMillis,
                executionProofSha256 = "",
            )
            return base.copy(executionProofSha256 = proofSha256(base)).also(::validateProof)
        } finally {
            runCatching { connectedHandle?.close() }
            registry.close()
        }
    }

    fun validateProof(proof: SiteProductionDeploymentRealVpsCommitTransactionExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(proof.executionReceiptConsumed && proof.commitPlanValidated && proof.stagingExecutionProofValidated)
        require(proof.freshCredentialResolutionProofValidated && proof.credentialLeaseMaterialConsumed)
        require(proof.productionNetworkTouched && proof.hostKeyPinVerifiedAgainstRemote && proof.freshSshSessionAcquisitionExecuted)
        require(proof.sftpChannelOpened && proof.sftpChannelClosed && proof.renameOnlyMutationBoundary)
        require(!proof.uploadPerformed && !proof.mkdirPerformed && !proof.deletePerformed)
        require(!proof.chmodPerformed && !proof.chownOrChgrpPerformed && !proof.remoteCommandDispatched)
        require(!proof.coordinatorInvoked && !proof.exposesDeployUiAction)
        require(proof.finalTargetVerified && proof.finalBackupVerified)
        when (proof.outcome) {
            SiteRemoteSftpCommitOutcome.COMMITTED -> require(!proof.rollbackPerformed && proof.stagingToTargetRenamePerformed)
            SiteRemoteSftpCommitOutcome.ROLLED_BACK -> require(proof.rollbackPerformed && proof.finalStagingVerified)
        }
        require(proof.renameOperationCount > 0 && proof.lstatOperationCount > 0)
        require(proof.executedAtEpochMillis >= proof.credentialResolvedAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.freshCredentialAuthorizationExpiresAtEpochMillis)
        validateHashes(
            proof.commitTransactionPlanSha256, proof.stagingWritePlanSha256, proof.stagingExecutionProofSha256,
            proof.sourceTreeSha256, proof.freshCredentialResolutionProofSha256,
            proof.freshCredentialResolutionConsumptionReceiptSha256, proof.serverAccessBindingSha256,
            proof.secretReferenceSha256, proof.pinnedHostKeySha256, proof.executionProofSha256,
        )
        proof.previousTargetTreeSha256?.let { require(sha256Pattern.matches(it)) }
        require(proof.executionProofSha256 == proofSha256(proof.copy(executionProofSha256 = "")))
    }

    private class OneShotLeaseSecretStore(
        private val expectedSecretId: SecretId,
        private val credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
    ) : SecretStore {
        private val readStarted = AtomicBoolean(false)
        override suspend fun read(secretId: SecretId): SecretReadResult {
            if (secretId != expectedSecretId) return SecretReadResult.NotFound
            if (!readStarted.compareAndSet(false, true)) return SecretReadResult.Unavailable("Ephemeral credential lease is single-use")
            val copy = credentialLease.useMaterialOnce { material -> material.useBytes { SecretMaterial.fromBytes(it) } }
            return SecretReadResult.Found(copy)
        }
        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Phase 11.53 lease adapter is read-only")
        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.53 lease adapter is read-only")
        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.53 lease adapter does not enumerate secrets")
    }

    private fun secretReferenceSha256(serverAccessId: String, type: String, secretId: String): String = sha256(buildString {
        append("serverAccessId=").append(serverAccessId).append('\n')
        append("secretReferenceType=").append(type).append('\n')
        append("secretId=").append(secretId).append('\n')
    })

    private fun serverAccessBindingSha256(serverAccess: ServerAccess, type: String, secretSha: String, pinSha: String): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("serverId=").append(serverAccess.serverId.value).append('\n')
        append("host=").append(serverAccess.endpoint.host).append('\n')
        append("port=").append(serverAccess.endpoint.port).append('\n')
        append("username=").append(serverAccess.username).append('\n')
        append("secretReferenceType=").append(type).append('\n')
        append("secretReferenceSha256=").append(secretSha).append('\n')
        append("pinnedHostKeySha256=").append(pinSha).append('\n')
    })

    private fun proofSha256(proof: SiteProductionDeploymentRealVpsCommitTransactionExecutionProof): String = sha256(buildString {
        append("phase=11.53\n")
        append("contractVersion=").append(proof.contractVersion).append('\n')
        append("outcome=").append(proof.outcome.name).append('\n')
        append("failureInjection=").append(proof.failureInjection.name).append('\n')
        append("commitPlan=").append(proof.commitTransactionPlanSha256).append('\n')
        append("stagingPlan=").append(proof.stagingWritePlanSha256).append('\n')
        append("stagingProof=").append(proof.stagingExecutionProofSha256).append('\n')
        append("tree=").append(proof.sourceTreeSha256).append('\n')
        append("previousTree=").append(proof.previousTargetTreeSha256 ?: "").append('\n')
        append("freshResolutionProof=").append(proof.freshCredentialResolutionProofSha256).append('\n')
        append("freshResolutionReceipt=").append(proof.freshCredentialResolutionConsumptionReceiptSha256).append('\n')
        append("binding=").append(proof.serverAccessBindingSha256).append('\n')
        append("serverAccessId=").append(proof.serverAccessId).append('\n')
        append("host=").append(proof.remoteHostIdentity).append('\n')
        append("port=").append(proof.remotePort).append('\n')
        append("username=").append(proof.username).append('\n')
        append("pin=").append(proof.pinnedHostKeySha256).append('\n')
        append("secretType=").append(proof.secretReferenceType).append('\n')
        append("secretSha=").append(proof.secretReferenceSha256).append('\n')
        append("target=").append(proof.targetRoot).append('\n')
        append("staging=").append(proof.stagingRoot).append('\n')
        append("backup=").append(proof.backupRoot ?: "").append('\n')
        append("lstat=").append(proof.lstatOperationCount).append('\n')
        append("list=").append(proof.listOperationCount).append('\n')
        append("read=").append(proof.readFileOperationCount).append('\n')
        append("rename=").append(proof.renameOperationCount).append('\n')
        append("targetToBackup=").append(proof.targetToBackupRenamePerformed).append('\n')
        append("stagingToTarget=").append(proof.stagingToTargetRenamePerformed).append('\n')
        append("targetToStagingRollback=").append(proof.targetToStagingRollbackRenamePerformed).append('\n')
        append("backupToTargetRollback=").append(proof.backupToTargetRollbackRenamePerformed).append('\n')
        append("rollback=").append(proof.rollbackPerformed).append('\n')
        append("backupRetained=").append(proof.backupRetainedAfterCommit).append('\n')
        append("sessionId=").append(proof.sessionId).append('\n')
        append("ownerId=").append(proof.operationOwnerId).append('\n')
        append("credentialResolvedAt=").append(proof.credentialResolvedAtEpochMillis).append('\n')
        append("executedAt=").append(proof.executedAtEpochMillis).append('\n')
        append("freshCredentialExpiresAt=").append(proof.freshCredentialAuthorizationExpiresAtEpochMillis).append('\n')
        append("upload=false\nmkdir=false\ndelete=false\nchmod=false\nchown=false\ncommand=false\ncoordinator=false\nui=false\n")
    })

    private fun validateHashes(vararg values: String) { require(values.all(sha256Pattern::matches)) }
    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.lowercase()
        return normalized == "localhost" || normalized == "::1" || normalized == "[::1]" || normalized.startsWith("127.")
    }
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray()).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

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
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWriteBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWritePlan
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsStagingWriteExecutionUsePort
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpStagingWriter
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/** First production mutation boundary: write and verify one exact Phase 11.51 bundle under staging only. */
internal object SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun stageVerifiedBundleOnce(
        preparation: SiteDeployerLocalPreparationResult,
        stagingPlan: SiteDeployerStagingWritePlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsStagingWriteExecutionUsePort,
    ): SiteProductionDeploymentRealVpsStagingWriteExecutionProof {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteDeployerStagingWriteBoundary.validate(stagingPlan, preparation.bundle)
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(freshResolutionProof)
        require(stagingPlan.preparationSha256 == preparation.preparationSha256)
        require(stagingPlan.deploymentPlanSha256 == preparation.remoteDeployPlan.deploymentPlanSha256)
        require(stagingPlan.sourceTreeSha256 == preparation.remoteDeployPlan.sourceTreeSha256)
        require(stagingPlan.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity)
        require(stagingPlan.targetRoot == preparation.remoteDeployPlan.publish.targetRoot)
        require(stagingPlan.stagingRoot == preparation.remoteDeployPlan.publish.stagingRoot)
        require(stagingPlan.remoteHostIdentity == serverAccess.endpoint.host)
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
        val secretReferenceSha256 = secretReferenceSha256(serverAccess.id.value, secretReferenceType, serverAccess.auth.secretId.value)
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
            is HostKeyFingerprintParseResult.Invalid -> throw IllegalArgumentException("Phase 11.52 pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        val bindingSha256 = serverAccessBindingSha256(serverAccess, secretReferenceType, secretReferenceSha256, expectedHostKeySha256)
        require(freshResolutionProof.serverAccessBindingSha256 == bindingSha256)

        // Burn before the single-use credential lease is read and before any production network activity.
        require(executionUsePort.consumeOnce(stagingPlan.stagingWritePlanSha256)) {
            "Phase 11.52 staging write was already attempted or durable first-use proof failed closed"
        }

        val ownerId = "phase11_52_${stagingPlan.stagingWritePlanSha256.take(24)}"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId("phase11_52_session_${stagingPlan.stagingWritePlanSha256.take(24)}")
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
                ?: throw IllegalArgumentException("Phase 11.52 fresh SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close(); throw IllegalArgumentException("Phase 11.52 missing verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256)
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)

            val evidence = SiteRemoteSftpStagingWriter().stage(
                session = verified,
                plan = stagingPlan,
                bundle = preparation.bundle,
                channelOpenTimeout = Duration.ofSeconds(5),
            )
            require(evidence.channelOpened && evidence.channelClosed)
            require(evidence.sourceTreeSha256 == stagingPlan.sourceTreeSha256)
            require(evidence.uploadedFileCount == stagingPlan.fileCount)
            require(evidence.verifiedFileCount == stagingPlan.fileCount)
            require(evidence.uploadedBytes == stagingPlan.totalBytes)
            require(!evidence.targetRootMutationPerformed && !evidence.renamePerformed && !evidence.deletePerformed)
            require(!evidence.chmodPerformed && !evidence.chownOrChgrpPerformed && !evidence.remoteCommandDispatched)

            val sessionIdValue = verified.binding.sessionId.value
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0 && !verified.isOpen)
            connectedHandle = null

            val base = SiteProductionDeploymentRealVpsStagingWriteExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentRealVpsStagingWriteExecutionStatus.REAL_VPS_STAGING_TREE_VERIFIED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
                executionReceiptConsumed = true,
                preparationValidated = true,
                stagingPlanValidated = true,
                freshCredentialResolutionProofValidated = true,
                credentialLeaseMaterialConsumed = true,
                productionNetworkTouched = true,
                hostKeyPinVerifiedAgainstRemote = true,
                freshSshSessionAcquisitionExecuted = true,
                sftpChannelOpened = true,
                sftpChannelClosed = true,
                stagingRootCreated = evidence.createdDirectoryCount > 0,
                exactFileSetUploaded = evidence.uploadedFileCount == stagingPlan.fileCount,
                remoteTreeVerified = evidence.sourceTreeSha256 == stagingPlan.sourceTreeSha256,
                targetRootMutationPerformed = false,
                renamePerformed = false,
                deletePerformed = false,
                chmodPerformed = false,
                chownOrChgrpPerformed = false,
                remoteCommandDispatched = false,
                commitPerformed = false,
                rollbackPerformed = false,
                sessionClosed = true,
                coordinatorInvoked = false,
                exposesDeployUiAction = false,
                requiresSeparateCommitBoundary = true,
                preparationSha256 = preparation.preparationSha256,
                deploymentPlanSha256 = preparation.remoteDeployPlan.deploymentPlanSha256,
                stagingWritePlanSha256 = stagingPlan.stagingWritePlanSha256,
                sourceTreeSha256 = stagingPlan.sourceTreeSha256,
                sourceArtifactSha256 = preparation.localExportReceipt.artifactSha256,
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
                targetRoot = stagingPlan.targetRoot,
                stagingRoot = stagingPlan.stagingRoot,
                fileCount = stagingPlan.fileCount,
                totalBytes = stagingPlan.totalBytes,
                createdDirectoryCount = evidence.createdDirectoryCount,
                uploadedFileCount = evidence.uploadedFileCount,
                verifiedFileCount = evidence.verifiedFileCount,
                lstatOperationCount = evidence.lstatOperationCount,
                listOperationCount = evidence.listOperationCount,
                readFileOperationCount = evidence.readFileOperationCount,
                writeFileOperationCount = evidence.writeFileOperationCount,
                mkdirOperationCount = evidence.mkdirOperationCount,
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

    fun validateProof(proof: SiteProductionDeploymentRealVpsStagingWriteExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(proof.status == SiteProductionDeploymentRealVpsStagingWriteExecutionStatus.REAL_VPS_STAGING_TREE_VERIFIED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY)
        require(proof.executionReceiptConsumed && proof.preparationValidated && proof.stagingPlanValidated)
        require(proof.freshCredentialResolutionProofValidated && proof.credentialLeaseMaterialConsumed)
        require(proof.productionNetworkTouched && proof.hostKeyPinVerifiedAgainstRemote && proof.freshSshSessionAcquisitionExecuted)
        require(proof.sftpChannelOpened && proof.sftpChannelClosed && proof.stagingRootCreated)
        require(proof.exactFileSetUploaded && proof.remoteTreeVerified)
        require(!proof.targetRootMutationPerformed && !proof.renamePerformed && !proof.deletePerformed)
        require(!proof.chmodPerformed && !proof.chownOrChgrpPerformed && !proof.remoteCommandDispatched)
        require(!proof.commitPerformed && !proof.rollbackPerformed && proof.sessionClosed)
        require(!proof.coordinatorInvoked && !proof.exposesDeployUiAction && proof.requiresSeparateCommitBoundary)
        require(proof.fileCount > 0 && proof.uploadedFileCount == proof.fileCount && proof.verifiedFileCount == proof.fileCount)
        require(proof.writeFileOperationCount == proof.fileCount && proof.readFileOperationCount == proof.fileCount)
        require(proof.totalBytes >= 0 && proof.mkdirOperationCount == proof.createdDirectoryCount)
        require(proof.verifiedHostKeySha256Compat())
        require(proof.executedAtEpochMillis >= proof.credentialResolvedAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.freshCredentialAuthorizationExpiresAtEpochMillis)
        validateHashes(
            proof.preparationSha256, proof.deploymentPlanSha256, proof.stagingWritePlanSha256,
            proof.sourceTreeSha256, proof.freshCredentialResolutionProofSha256,
            proof.freshCredentialResolutionConsumptionReceiptSha256, proof.serverAccessBindingSha256,
            proof.secretReferenceSha256, proof.pinnedHostKeySha256, proof.executionProofSha256,
        )
        proof.sourceArtifactSha256?.let { require(sha256Pattern.matches(it)) }
        require(proof.executionProofSha256 == proofSha256(proof.copy(executionProofSha256 = "")))
    }

    private fun SiteProductionDeploymentRealVpsStagingWriteExecutionProof.verifiedHostKeySha256Compat(): Boolean =
        pinnedHostKeySha256.isNotBlank()

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
            SecretCreateResult.StorageFailure("Phase 11.52 lease adapter is read-only")
        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.52 lease adapter is read-only")
        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.52 lease adapter does not enumerate secrets")
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

    private fun proofSha256(proof: SiteProductionDeploymentRealVpsStagingWriteExecutionProof): String = sha256(buildString {
        append("phase=11.52\n")
        append("contractVersion=").append(proof.contractVersion).append('\n')
        append("status=").append(proof.status.name).append('\n')
        append("preparation=").append(proof.preparationSha256).append('\n')
        append("deploymentPlan=").append(proof.deploymentPlanSha256).append('\n')
        append("stagingPlan=").append(proof.stagingWritePlanSha256).append('\n')
        append("tree=").append(proof.sourceTreeSha256).append('\n')
        append("artifact=").append(proof.sourceArtifactSha256 ?: "").append('\n')
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
        append("files=").append(proof.fileCount).append('\n')
        append("bytes=").append(proof.totalBytes).append('\n')
        append("dirs=").append(proof.createdDirectoryCount).append('\n')
        append("uploaded=").append(proof.uploadedFileCount).append('\n')
        append("verified=").append(proof.verifiedFileCount).append('\n')
        append("lstat=").append(proof.lstatOperationCount).append('\n')
        append("list=").append(proof.listOperationCount).append('\n')
        append("read=").append(proof.readFileOperationCount).append('\n')
        append("write=").append(proof.writeFileOperationCount).append('\n')
        append("mkdir=").append(proof.mkdirOperationCount).append('\n')
        append("sessionId=").append(proof.sessionId).append('\n')
        append("ownerId=").append(proof.operationOwnerId).append('\n')
        append("credentialResolvedAt=").append(proof.credentialResolvedAtEpochMillis).append('\n')
        append("executedAt=").append(proof.executedAtEpochMillis).append('\n')
        append("freshCredentialExpiresAt=").append(proof.freshCredentialAuthorizationExpiresAtEpochMillis).append('\n')
        append("commit=false\nrollback=false\nrename=false\ndelete=false\nchmod=false\nchown=false\ncommand=false\n")
    })

    private fun validateHashes(vararg values: String) { require(values.all(sha256Pattern::matches)) }
    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.lowercase(); return normalized == "localhost" || normalized == "::1" || normalized == "[::1]" || normalized.startsWith("127.")
    }
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray()).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

internal object SiteProductionDeploymentAndroidSftpReadOnlyPreflightExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun observeFixtureReadOnlyPreflightOnce(
        receipt: SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentSftpReadOnlyPreflightExecutionProof {
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightHandoffConsumptionBoundary.validateReceipt(receipt)
        require(serverAccess.id.value == receipt.serverAccessId && serverAccess.endpoint.host == receipt.remoteHostIdentity && serverAccess.endpoint.port == receipt.remotePort)
        require(serverAccess.endpoint.host == SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.FIXTURE_LOOPBACK_HOST)
        require(credentialLease.serverAccessId == receipt.serverAccessId)
        require(credentialLease.secretReferenceType == receipt.secretReferenceType && credentialLease.secretReferenceSha256 == receipt.secretReferenceSha256)
        require(executedAtEpochMillis >= receipt.consumedAtEpochMillis && executedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis)
        require(executedAtEpochMillis <= credentialLease.authorizationExpiresAtEpochMillis)
        require(canonicalId.matches(executionAttemptId))
        require(receipt.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        val secretType = when (serverAccess.auth) { is SshAuthRef.Password -> "password"; is SshAuthRef.PrivateKey -> "private-key" }
        require(secretType == receipt.secretReferenceType)
        require(secretReferenceSha256(serverAccess, secretType) == receipt.secretReferenceSha256)
        require(serverAccessBindingSha256(serverAccess, receipt) == receipt.serverAccessBindingSha256)
        val expectedHostKey = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid -> throw IllegalArgumentException("Read-only SFTP preflight pinned host key is invalid")
        }
        val ownerId = "phase11_35_$executionAttemptId"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId("phase11_35_session_${receipt.authorizationSha256.take(24)}")
        val leaseStore = OneShotLeaseSecretStore(serverAccess.auth.secretId, credentialLease)
        val factory = JschSshConnectionFactory(leaseStore) { deterministicSessionId }
        val registry = ExactSessionRegistry()
        var connectedHandle: VerifiedHostKeySshSessionHandle? = null
        try {
            val result = factory.connect(serverAccess, owner, SshTransportConfig(
                tcpConnectTimeout = Duration.ofSeconds(5), handshakeAndAuthTimeout = Duration.ofSeconds(7),
                channelOpenTimeout = Duration.ofSeconds(5), commandExecutionTimeout = Duration.ofSeconds(5),
                stdoutCaptureLimitBytes = 4096, stderrCaptureLimitBytes = 4096))
            val connected = result as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Read-only SFTP fixture SSH acquisition failed: " + ((result as SshConnectResult.Failed).failure::class.java.simpleName))
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run { connected.handle.close(); error("Missing verified host-key evidence") }
            connectedHandle = verified
            require(verified.isOpen && verified.binding.serverAccessId == serverAccess.id && verified.binding.owner == owner && verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKey.asHexSha256())
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)
            val evidence = SiteRemoteSftpReadOnlyPreflightProbe().observe(
                session = verified, targetRoot = receipt.targetRoot, stagingRoot = receipt.stagingRoot,
                backupRoot = receipt.backupRoot, expectedTargetEntryNames = receipt.expectedTargetEntryNames,
                channelOpenTimeout = Duration.ofSeconds(5),
            )
            require(evidence.channelOpened && evidence.channelClosed)
            require(evidence.lstatOperationCount == 3 && evidence.listOperationCount == 1)
            require(!evidence.mutationOperationPerformed && !evidence.remoteCommandDispatched)
            val observationSha = observationSha256(evidence)
            val sessionId = verified.binding.sessionId.value
            val hostKey = verified.verifiedHostKeySha256
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0 && !verified.isOpen)
            connectedHandle = null
            val base = SiteProductionDeploymentSftpReadOnlyPreflightExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentSftpReadOnlyPreflightExecutionStatus.FIXTURE_READ_ONLY_SFTP_PREFLIGHT_VERIFIED,
                fixtureEndpointRequired = true, credentialLeaseMaterialConsumed = true, productionSshAdapterUsed = true,
                exactSessionRegistryUsed = true, sessionRegistered = true, exactRegistryLookupMatched = true,
                sftpChannelOpened = true, sftpChannelClosed = true, lstatOperationCount = 3, listOperationCount = 1,
                mutationOperationPerformed = false, remoteCommandDispatched = false, sessionClosed = true,
                coordinatorInvoked = false, exposesDeployUiAction = false, realVpsAccessAllowed = false,
                requiresSeparateMutationBoundary = true, authorizationSha256 = receipt.authorizationSha256,
                consumptionReceiptSha256 = receipt.consumptionReceiptSha256,
                sftpChannelOpenConsumptionReceiptSha256 = receipt.sftpChannelOpenConsumptionReceiptSha256,
                requestSha256 = receipt.requestSha256, serverAccessBindingSha256 = receipt.serverAccessBindingSha256,
                serverAccessId = receipt.serverAccessId, remoteHostIdentity = receipt.remoteHostIdentity, remotePort = receipt.remotePort,
                sftpReadOnlyProbeImplementation = SiteRemoteSftpReadOnlyPreflightProbe::class.java.name,
                targetRoot = evidence.target.path, targetType = evidence.target.type,
                stagingRoot = evidence.staging.path, stagingType = evidence.staging.type,
                backupRoot = evidence.backup.path, backupType = evidence.backup.type,
                targetEntryNames = evidence.targetEntryNames, observationSha256 = observationSha,
                sessionId = sessionId, operationOwnerId = ownerId, verifiedHostKeySha256 = hostKey,
                executedAtEpochMillis = executedAtEpochMillis, executionProofSha256 = "",
            )
            return base.copy(executionProofSha256 = proofSha256(base)).also(::validateProof)
        } finally { runCatching { connectedHandle?.close() }; registry.close() }
    }

    fun validateProof(p: SiteProductionDeploymentSftpReadOnlyPreflightExecutionProof) {
        require(p.contractVersion == CONTRACT_VERSION && p.status == SiteProductionDeploymentSftpReadOnlyPreflightExecutionStatus.FIXTURE_READ_ONLY_SFTP_PREFLIGHT_VERIFIED)
        require(p.fixtureEndpointRequired && p.credentialLeaseMaterialConsumed && p.productionSshAdapterUsed)
        require(p.exactSessionRegistryUsed && p.sessionRegistered && p.exactRegistryLookupMatched)
        require(p.sftpChannelOpened && p.sftpChannelClosed && p.lstatOperationCount == 3 && p.listOperationCount == 1)
        require(!p.mutationOperationPerformed && !p.remoteCommandDispatched && p.sessionClosed)
        require(!p.coordinatorInvoked && !p.exposesDeployUiAction && !p.realVpsAccessAllowed && p.requiresSeparateMutationBoundary)
        require(p.remoteHostIdentity == SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.FIXTURE_LOOPBACK_HOST && p.remotePort in 1..65535)
        require(p.targetType == com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.DIRECTORY)
        require(p.stagingType == com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.ABSENT)
        require(p.backupType == com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.ABSENT)
        validateHashes(p.authorizationSha256, p.consumptionReceiptSha256, p.sftpChannelOpenConsumptionReceiptSha256, p.requestSha256,
            p.serverAccessBindingSha256, p.observationSha256, p.verifiedHostKeySha256, p.executionProofSha256)
        require(p.executionProofSha256 == proofSha256(p.copy(executionProofSha256 = "")))
    }

    private class OneShotLeaseSecretStore(private val expectedSecretId: SecretId, private val lease: SiteProductionDeploymentEphemeralCredentialLease): SecretStore {
        private val readStarted = AtomicBoolean(false)
        override suspend fun read(secretId: SecretId): SecretReadResult {
            if (secretId != expectedSecretId) return SecretReadResult.NotFound
            if (!readStarted.compareAndSet(false, true)) return SecretReadResult.Unavailable("Ephemeral credential lease is single-use")
            return SecretReadResult.Found(lease.useMaterialOnce { m -> m.useBytes { SecretMaterial.fromBytes(it) } })
        }
        override suspend fun create(secretId: SecretId, material: SecretMaterial) = SecretCreateResult.StorageFailure("Phase 11.35 lease adapter is read-only")
        override suspend fun delete(secretId: SecretId) = SecretDeleteResult.StorageFailure("Phase 11.35 lease adapter is read-only")
        override suspend fun listIds() = SecretListResult.StorageFailure("Phase 11.35 lease adapter does not enumerate secrets")
    }
    private fun secretReferenceSha256(a: ServerAccess, type: String) = sha256("serverAccessId=${a.id.value}\nsecretReferenceType=$type\nsecretId=${a.auth.secretId.value}\n")
    private fun serverAccessBindingSha256(a: ServerAccess, r: SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt) = sha256(buildString {
        append("serverAccessId=").append(a.id.value).append('\n'); append("serverId=").append(a.serverId.value).append('\n'); append("host=").append(a.endpoint.host).append('\n'); append("port=").append(a.endpoint.port).append('\n'); append("username=").append(a.username).append('\n'); append("secretReferenceType=").append(r.secretReferenceType).append('\n'); append("secretReferenceSha256=").append(r.secretReferenceSha256).append('\n'); append("pinnedHostKey=").append(a.pinnedHostKey.value).append('\n')
    })
    private fun observationSha256(e: SiteRemoteSftpReadOnlyPreflightEvidence) = sha256(buildString {
        listOf(e.target, e.staging, e.backup).forEach { p -> append("path=").append(p.path).append('|').append(p.type.name).append('|').append(p.sizeBytes).append('|').append(p.uid).append('|').append(p.gid).append('|').append(p.permissions).append('\n') }
        e.targetEntryNames.forEach { append("entry=").append(it).append('\n') }
        append("lstat=").append(e.lstatOperationCount).append('\n'); append("list=").append(e.listOperationCount).append('\n')
    })
    private fun proofSha256(p: SiteProductionDeploymentSftpReadOnlyPreflightExecutionProof) = sha256(buildString {
        append("contractVersion=").append(p.contractVersion).append('\n'); append("status=").append(p.status.name).append('\n'); append("authorization=").append(p.authorizationSha256).append('\n'); append("consumption=").append(p.consumptionReceiptSha256).append('\n'); append("sftpReceipt=").append(p.sftpChannelOpenConsumptionReceiptSha256).append('\n'); append("request=").append(p.requestSha256).append('\n'); append("binding=").append(p.serverAccessBindingSha256).append('\n'); append("serverAccessId=").append(p.serverAccessId).append('\n'); append("host=").append(p.remoteHostIdentity).append('\n'); append("port=").append(p.remotePort).append('\n'); append("probe=").append(p.sftpReadOnlyProbeImplementation).append('\n'); append("observation=").append(p.observationSha256).append('\n'); append("sessionId=").append(p.sessionId).append('\n'); append("ownerId=").append(p.operationOwnerId).append('\n'); append("hostKey=").append(p.verifiedHostKeySha256).append('\n'); append("executedAt=").append(p.executedAtEpochMillis).append('\n'); append("lstat=").append(p.lstatOperationCount).append('\n'); append("list=").append(p.listOperationCount).append('\n'); append("mutation=").append(p.mutationOperationPerformed).append('\n'); append("command=").append(p.remoteCommandDispatched).append('\n'); append("realVps=").append(p.realVpsAccessAllowed).append('\n')
    })
    private fun validateHashes(vararg values: String) = require(values.all(sha256Pattern::matches))
    private fun sha256(v: String) = MessageDigest.getInstance("SHA-256").digest(v.encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

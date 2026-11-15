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
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpChannelLifecycleProbe
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Phase 11.34 fixture-only execution of one explicitly approved + durably consumed SFTP channel open.
 * The channel is opened and closed without invoking any SFTP path operation or remote exec command.
 */
internal object SiteProductionDeploymentAndroidSftpChannelOpenExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun openFixtureSftpChannelOnce(
        receipt: SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentSftpChannelOpenExecutionProof {
        SiteProductionDeploymentAndroidSftpChannelOpenHandoffConsumptionBoundary.validateReceipt(receipt)
        require(receipt.singleUseConsumed)
        require(receipt.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(serverAccess.id.value == receipt.serverAccessId) { "SFTP execution ServerAccess mismatch" }
        require(serverAccess.endpoint.host == receipt.remoteHostIdentity) { "SFTP execution host mismatch" }
        require(serverAccess.endpoint.host == SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.FIXTURE_LOOPBACK_HOST) {
            "Phase 11.34 executes only against the adb-reverse loopback fixture"
        }
        require(serverAccess.endpoint.port == receipt.remotePort && receipt.remotePort in 1..65535) {
            "SFTP execution fixture port mismatch"
        }
        require(credentialLease.serverAccessId == receipt.serverAccessId)
        require(credentialLease.secretReferenceType == receipt.secretReferenceType)
        require(credentialLease.secretReferenceSha256 == receipt.secretReferenceSha256)
        require(credentialLease.resolvedAtEpochMillis <= receipt.consumedAtEpochMillis)
        require(executedAtEpochMillis >= receipt.consumedAtEpochMillis)
        require(executedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis)
        require(executedAtEpochMillis <= credentialLease.authorizationExpiresAtEpochMillis)
        require(canonicalId.matches(executionAttemptId)) { "SFTP execution attempt id must be canonical" }
        require(receipt.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(receipt.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(receipt.sftpLifecycleProbeImplementation == SiteRemoteSftpChannelLifecycleProbe::class.java.name)

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == receipt.secretReferenceType)
        require(secretReferenceSha256(serverAccess, secretReferenceType) == receipt.secretReferenceSha256) {
            "SFTP execution raw SecretId binding mismatch"
        }
        require(serverAccessBindingSha256(serverAccess, receipt) == receipt.serverAccessBindingSha256) {
            "SFTP execution ServerAccess binding mismatch"
        }
        val expectedHostKey = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid -> throw IllegalArgumentException("SFTP execution pinned host key is invalid")
        }

        val ownerId = "phase11_34_$executionAttemptId"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId("phase11_34_session_${receipt.authorizationSha256.take(24)}")
        val leaseStore = OneShotLeaseSecretStore(serverAccess.auth.secretId, credentialLease)
        val factory = JschSshConnectionFactory(leaseStore) { deterministicSessionId }
        val registry = ExactSessionRegistry()
        var connectedHandle: VerifiedHostKeySshSessionHandle? = null
        try {
            val connectResult = factory.connect(
                access = serverAccess,
                owner = owner,
                config = SshTransportConfig(
                    tcpConnectTimeout = Duration.ofSeconds(5),
                    handshakeAndAuthTimeout = Duration.ofSeconds(7),
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(5),
                    stdoutCaptureLimitBytes = 4096,
                    stderrCaptureLimitBytes = 4096,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException(
                    "SFTP fixture SSH acquisition failed: " +
                        ((connectResult as SshConnectResult.Failed).failure::class.java.simpleName),
                )
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException("SFTP execution did not receive verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKey.asHexSha256())
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)

            val lifecycle = SiteRemoteSftpChannelLifecycleProbe().openAndClose(
                session = verified,
                channelOpenTimeout = Duration.ofSeconds(5),
            )
            require(lifecycle.channelOpened && lifecycle.channelClosed)
            require(!lifecycle.sftpOperationPerformed)

            val sessionIdValue = verified.binding.sessionId.value
            val verifiedHostKeySha256 = verified.verifiedHostKeySha256
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0)
            require(!verified.isOpen)
            connectedHandle = null

            val base = SiteProductionDeploymentSftpChannelOpenExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentSftpChannelOpenExecutionStatus.FIXTURE_SFTP_CHANNEL_OPENED_AND_CLOSED,
                fixtureEndpointRequired = true,
                credentialLeaseMaterialConsumed = true,
                productionSshAdapterUsed = true,
                sshSessionAcquisitionExecuted = true,
                exactSessionRegistryUsed = true,
                sessionRegistered = true,
                exactRegistryLookupMatched = true,
                sftpChannelOpened = true,
                sftpChannelClosed = true,
                sftpOperationPerformed = false,
                remoteCommandDispatched = false,
                sessionClosed = true,
                coordinatorInvoked = false,
                exposesDeployUiAction = false,
                realVpsAccessAllowed = false,
                requiresSeparateBoundedSftpOperationsBoundary = true,
                requiresSeparateCoordinatorInvocationBoundary = true,
                authorizationSha256 = receipt.authorizationSha256,
                sftpChannelOpenConsumptionReceiptSha256 = receipt.sftpChannelOpenConsumptionReceiptSha256,
                sshSessionAcquisitionConsumptionReceiptSha256 = receipt.sshSessionAcquisitionConsumptionReceiptSha256,
                resolutionProofSha256 = receipt.resolutionProofSha256,
                serverAccessBindingSha256 = receipt.serverAccessBindingSha256,
                serverAccessId = receipt.serverAccessId,
                remoteHostIdentity = receipt.remoteHostIdentity,
                remotePort = receipt.remotePort,
                secretReferenceType = receipt.secretReferenceType,
                secretReferenceSha256 = receipt.secretReferenceSha256,
                sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
                exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
                sftpLifecycleProbeImplementation = SiteRemoteSftpChannelLifecycleProbe::class.java.name,
                sessionId = sessionIdValue,
                operationOwnerId = ownerId,
                verifiedHostKeySha256 = verifiedHostKeySha256,
                executedAtEpochMillis = executedAtEpochMillis,
                executionProofSha256 = "",
            )
            return base.copy(executionProofSha256 = proofSha256(base)).also(::validateProof)
        } finally {
            runCatching { connectedHandle?.close() }
            registry.close()
        }
    }

    fun validateProof(proof: SiteProductionDeploymentSftpChannelOpenExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(proof.status == SiteProductionDeploymentSftpChannelOpenExecutionStatus.FIXTURE_SFTP_CHANNEL_OPENED_AND_CLOSED)
        require(proof.fixtureEndpointRequired)
        require(proof.credentialLeaseMaterialConsumed)
        require(proof.productionSshAdapterUsed && proof.sshSessionAcquisitionExecuted)
        require(proof.exactSessionRegistryUsed && proof.sessionRegistered && proof.exactRegistryLookupMatched)
        require(proof.sftpChannelOpened && proof.sftpChannelClosed)
        require(!proof.sftpOperationPerformed && !proof.remoteCommandDispatched)
        require(proof.sessionClosed)
        require(!proof.coordinatorInvoked && !proof.exposesDeployUiAction && !proof.realVpsAccessAllowed)
        require(proof.requiresSeparateBoundedSftpOperationsBoundary)
        require(proof.requiresSeparateCoordinatorInvocationBoundary)
        require(proof.remoteHostIdentity == SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.FIXTURE_LOOPBACK_HOST)
        require(proof.remotePort in 1..65535)
        validateHashes(
            proof.authorizationSha256,
            proof.sftpChannelOpenConsumptionReceiptSha256,
            proof.sshSessionAcquisitionConsumptionReceiptSha256,
            proof.resolutionProofSha256,
            proof.serverAccessBindingSha256,
            proof.secretReferenceSha256,
            proof.verifiedHostKeySha256,
            proof.executionProofSha256,
        )
        require(proof.executionProofSha256 == proofSha256(proof.copy(executionProofSha256 = ""))) {
            "SFTP channel-open execution proof SHA-256 mismatch"
        }
    }

    private class OneShotLeaseSecretStore(
        private val expectedSecretId: SecretId,
        private val credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
    ) : SecretStore {
        private val readStarted = AtomicBoolean(false)
        override suspend fun read(secretId: SecretId): SecretReadResult {
            if (secretId != expectedSecretId) return SecretReadResult.NotFound
            if (!readStarted.compareAndSet(false, true)) return SecretReadResult.Unavailable("Ephemeral credential lease is single-use")
            val copy = credentialLease.useMaterialOnce { material ->
                material.useBytes { SecretMaterial.fromBytes(it) }
            }
            return SecretReadResult.Found(copy)
        }
        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Phase 11.34 lease adapter is read-only")
        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.34 lease adapter is read-only")
        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.34 lease adapter does not enumerate secrets")
    }

    private fun secretReferenceSha256(serverAccess: ServerAccess, type: String): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("secretReferenceType=").append(type).append('\n')
        append("secretId=").append(serverAccess.auth.secretId.value).append('\n')
    })

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        receipt: SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt,
    ): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("serverId=").append(serverAccess.serverId.value).append('\n')
        append("host=").append(serverAccess.endpoint.host).append('\n')
        append("port=").append(serverAccess.endpoint.port).append('\n')
        append("username=").append(serverAccess.username).append('\n')
        append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
        append("pinnedHostKey=").append(serverAccess.pinnedHostKey.value).append('\n')
    })

    private fun proofSha256(proof: SiteProductionDeploymentSftpChannelOpenExecutionProof): String = sha256(buildString {
        append("contractVersion=").append(proof.contractVersion).append('\n')
        append("status=").append(proof.status.name).append('\n')
        append("authorizationSha256=").append(proof.authorizationSha256).append('\n')
        append("consumptionReceipt=").append(proof.sftpChannelOpenConsumptionReceiptSha256).append('\n')
        append("sshReceipt=").append(proof.sshSessionAcquisitionConsumptionReceiptSha256).append('\n')
        append("resolutionProof=").append(proof.resolutionProofSha256).append('\n')
        append("serverAccessBinding=").append(proof.serverAccessBindingSha256).append('\n')
        append("serverAccessId=").append(proof.serverAccessId).append('\n')
        append("host=").append(proof.remoteHostIdentity).append('\n')
        append("port=").append(proof.remotePort).append('\n')
        append("secretReferenceType=").append(proof.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(proof.secretReferenceSha256).append('\n')
        append("sshFactory=").append(proof.sshConnectionFactoryImplementation).append('\n')
        append("registry=").append(proof.exactSessionRegistryImplementation).append('\n')
        append("sftpProbe=").append(proof.sftpLifecycleProbeImplementation).append('\n')
        append("sessionId=").append(proof.sessionId).append('\n')
        append("ownerId=").append(proof.operationOwnerId).append('\n')
        append("verifiedHostKey=").append(proof.verifiedHostKeySha256).append('\n')
        append("executedAt=").append(proof.executedAtEpochMillis).append('\n')
        append("credentialLeaseMaterialConsumed=").append(proof.credentialLeaseMaterialConsumed).append('\n')
        append("sftpChannelOpened=").append(proof.sftpChannelOpened).append('\n')
        append("sftpChannelClosed=").append(proof.sftpChannelClosed).append('\n')
        append("sftpOperationPerformed=").append(proof.sftpOperationPerformed).append('\n')
        append("remoteCommandDispatched=").append(proof.remoteCommandDispatched).append('\n')
        append("sessionClosed=").append(proof.sessionClosed).append('\n')
        append("realVpsAccessAllowed=").append(proof.realVpsAccessAllowed).append('\n')
    })

    private fun validateHashes(vararg values: String) = require(values.all(sha256Pattern::matches)) {
        "SFTP channel-open execution hashes must be lowercase SHA-256"
    }
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

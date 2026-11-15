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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsSftpChannelOpenExecutionUsePort
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
 * Phase 11.47 executes exactly one already-approved + durably-consumed real-VPS SFTP channel open.
 *
 * Counteraction precedes action: the exact Phase 11.46 receipt is durably burned in a dedicated
 * execution namespace before credential material can be read or production network can be touched.
 * The boundary requires a credential-resolution proof and ephemeral lease created after Phase 11.46
 * consumption, then performs one fresh production JSch SSH acquisition with live host-key pin
 * verification. One SFTP channel is opened and closed through SiteRemoteSftpChannelLifecycleProbe;
 * no SFTP path operation, remote command, remote read, mutation, coordinator invocation or deploy UI
 * is permitted here. The SSH session is exact-registered, exact-looked-up, removed and closed.
 */
internal object SiteProductionDeploymentAndroidRealVpsSftpChannelOpenExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun openRealVpsSftpChannelOnce(
        receipt: SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionReceipt,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsSftpChannelOpenExecutionUsePort,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenExecutionProof {
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenHandoffConsumptionBoundary
            .validateReceipt(receipt)
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
            .validateProof(freshResolutionProof)

        require(receipt.singleUseConsumed)
        require(receipt.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution)
        require(receipt.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution)
        require(receipt.requiresFreshLiveRemoteHostKeyVerificationBeforeSftpChannelOpenExecution)
        require(receipt.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(!receipt.authorizesReadOnlyPreflightExecution)
        require(!receipt.authorizesMutation)
        require(!receipt.authorizesCoordinatorInvocation)
        require(!receipt.exposesDeployUiAction)

        require(
            freshResolutionProof.status ==
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.RESOLVED_TO_EPHEMERAL_LEASE,
        ) { "Phase 11.47 requires a successful fresh credential-resolution proof" }
        require(freshResolutionProof.secretStoreReadPerformed)
        require(!freshResolutionProof.credentialLeaseMaterialRead)
        require(!freshResolutionProof.productionNetworkTouched)
        require(freshResolutionProof.requiresLiveRemoteHostKeyVerification)
        require(freshResolutionProof.requiresSeparateSshSessionAcquisitionBoundary)
        require(freshResolutionProof.requiresSeparateSftpChannelOpenBoundary)
        require(freshResolutionProof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(freshResolutionProof.resolvedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "Real-VPS SFTP execution requires credential resolution after Phase 11.46 consumption"
        }
        require(freshResolutionProof.resolvedAtEpochMillis <= executedAtEpochMillis) {
            "Real-VPS SFTP execution cannot predate fresh credential resolution"
        }
        require(executedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "Real-VPS SFTP execution cannot predate durable handoff consumption"
        }
        require(executedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "Real-VPS SFTP authorization window expired before execution"
        }
        require(executedAtEpochMillis <= freshResolutionProof.authorizationExpiresAtEpochMillis) {
            "Fresh credential-resolution authorization expired before SFTP execution"
        }
        require(canonicalId.matches(executionAttemptId)) {
            "Real-VPS SFTP execution attempt id must be a canonical 8..128 character identifier"
        }

        require(serverAccess.id.value == receipt.serverAccessId) { "Real-VPS SFTP ServerAccess mismatch" }
        require(serverAccess.endpoint.host == receipt.remoteHostIdentity) { "Real-VPS SFTP host mismatch" }
        require(serverAccess.endpoint.port == receipt.remotePort && receipt.remotePort in 1..65535) {
            "Real-VPS SFTP port mismatch"
        }
        require(serverAccess.username == receipt.username) { "Real-VPS SFTP username mismatch" }
        require(!isLoopbackHost(serverAccess.endpoint.host)) {
            "Phase 11.47 requires the exact reviewed non-loopback real-VPS endpoint"
        }
        require(receipt.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(receipt.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(receipt.sftpLifecycleProbeImplementation == SiteRemoteSftpChannelLifecycleProbe::class.java.name)

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == receipt.secretReferenceType)
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        require(secretReferenceSha256 == receipt.secretReferenceSha256) {
            "Real-VPS SFTP raw SecretId binding mismatch"
        }

        val expectedHostKey = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid ->
                throw IllegalArgumentException("Real-VPS SFTP pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        require(expectedHostKeySha256 == receipt.pinnedHostKeySha256) {
            "Real-VPS SFTP pinned host-key binding drifted"
        }
        require(
            serverAccessBindingSha256(
                serverAccess = serverAccess,
                secretReferenceType = secretReferenceType,
                secretReferenceSha256 = secretReferenceSha256,
                pinnedHostKeySha256 = expectedHostKeySha256,
            ) == receipt.serverAccessBindingSha256,
        ) { "Real-VPS SFTP ServerAccess binding drifted after authorization" }

        require(freshResolutionProof.serverAccessId == receipt.serverAccessId)
        require(freshResolutionProof.serverAccessBindingSha256 == receipt.serverAccessBindingSha256)
        require(freshResolutionProof.requestSha256 == receipt.requestSha256)
        require(freshResolutionProof.capabilityProfileSha256 == receipt.capabilityProfileSha256)
        require(freshResolutionProof.secretReferenceType == receipt.secretReferenceType)
        require(freshResolutionProof.secretReferenceSha256 == receipt.secretReferenceSha256)
        require(freshCredentialLease.serverAccessId == receipt.serverAccessId)
        require(freshCredentialLease.secretReferenceType == receipt.secretReferenceType)
        require(freshCredentialLease.secretReferenceSha256 == receipt.secretReferenceSha256)
        require(
            freshCredentialLease.credentialResolutionConsumptionReceiptSha256 ==
                freshResolutionProof.credentialResolutionConsumptionReceiptSha256,
        ) { "Fresh credential lease is not bound to the supplied resolution proof" }
        require(freshCredentialLease.resolvedAtEpochMillis == freshResolutionProof.resolvedAtEpochMillis)
        require(
            freshCredentialLease.authorizationExpiresAtEpochMillis ==
                freshResolutionProof.authorizationExpiresAtEpochMillis,
        )

        // Durable burn before material read or network. Uncertain execution therefore fails closed
        // after restart and the exact Phase 11.46 receipt cannot be replayed for a second SFTP open.
        require(
            executionUsePort.consumeOnce(receipt.sftpChannelOpenConsumptionReceiptSha256),
        ) { "Real-VPS SFTP execution receipt was already used or replay fence failed closed" }

        val ownerId = "phase11_47_$executionAttemptId"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId(
            "phase11_47_session_${receipt.sftpChannelOpenConsumptionReceiptSha256.take(24)}",
        )
        val leaseStore = OneShotLeaseSecretStore(
            expectedSecretId = serverAccess.auth.secretId,
            credentialLease = freshCredentialLease,
        )
        val factory = JschSshConnectionFactory(
            secretStore = leaseStore,
            sessionIdFactory = { deterministicSessionId },
        )
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
                ?: throw IllegalArgumentException(
                    "Real-VPS SFTP fresh SSH acquisition failed closed: " +
                        ((connectResult as SshConnectResult.Failed).failure::class.java.simpleName),
                )
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException(
                    "Real-VPS SFTP execution did not receive verified host-key evidence",
                )
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256) {
                "Real-VPS SFTP fresh live host-key verification did not match the reviewed pin"
            }
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
            require(
                registry.remove(
                    owner = owner,
                    accessId = serverAccess.id,
                    sessionId = verified.binding.sessionId,
                    close = true,
                ),
            )
            require(registry.size() == 0)
            require(!verified.isOpen)
            connectedHandle = null

            val base = SiteProductionDeploymentRealVpsSftpChannelOpenExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentRealVpsSftpChannelOpenExecutionStatus
                    .REAL_VPS_SFTP_CHANNEL_OPENED_AND_CLOSED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
                durableHandoffConsumed = true,
                executionReceiptConsumed = true,
                freshCredentialResolutionProofValidated = true,
                credentialLeaseMaterialConsumed = true,
                productionNetworkTouched = true,
                hostKeyPinVerifiedAgainstRemote = true,
                productionSshAdapterUsed = true,
                freshSshSessionAcquisitionExecuted = true,
                exactSessionRegistryUsed = true,
                sessionRegistered = true,
                exactRegistryLookupMatched = true,
                sftpChannelOpened = true,
                sftpChannelClosed = true,
                sftpOperationPerformed = false,
                remoteCommandDispatched = false,
                remoteReadPerformed = false,
                mutationPerformed = false,
                sessionClosed = true,
                coordinatorInvoked = false,
                exposesDeployUiAction = false,
                realVpsAccessPerformed = true,
                requiresSeparateReadOnlyExecutionBoundary = true,
                requiresSeparateMutationBoundary = true,
                authorizationSha256 = receipt.authorizationSha256,
                sftpChannelOpenConsumptionReceiptSha256 =
                    receipt.sftpChannelOpenConsumptionReceiptSha256,
                freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
                freshCredentialResolutionConsumptionReceiptSha256 =
                    freshResolutionProof.credentialResolutionConsumptionReceiptSha256,
                priorSshExecutionProofSha256 = receipt.priorSshExecutionProofSha256,
                priorSshExecutionReceiptSha256 = receipt.priorSshExecutionReceiptSha256,
                serverAccessBindingSha256 = receipt.serverAccessBindingSha256,
                requestSha256 = receipt.requestSha256,
                capabilityProfileSha256 = receipt.capabilityProfileSha256,
                serverAccessId = receipt.serverAccessId,
                remoteHostIdentity = receipt.remoteHostIdentity,
                remotePort = receipt.remotePort,
                username = receipt.username,
                pinnedHostKeySha256 = receipt.pinnedHostKeySha256,
                secretReferenceType = receipt.secretReferenceType,
                secretReferenceSha256 = receipt.secretReferenceSha256,
                credentialStoreImplementation = freshResolutionProof.credentialStoreImplementation,
                sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
                exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
                sftpLifecycleProbeImplementation = SiteRemoteSftpChannelLifecycleProbe::class.java.name,
                sessionId = sessionIdValue,
                operationOwnerId = ownerId,
                verifiedHostKeySha256 = verifiedHostKeySha256,
                credentialResolvedAtEpochMillis = freshResolutionProof.resolvedAtEpochMillis,
                handoffConsumedAtEpochMillis = receipt.consumedAtEpochMillis,
                executedAtEpochMillis = executedAtEpochMillis,
                authorizationExpiresAtEpochMillis = receipt.authorizationExpiresAtEpochMillis,
                freshCredentialAuthorizationExpiresAtEpochMillis =
                    freshResolutionProof.authorizationExpiresAtEpochMillis,
                executionProofSha256 = "",
            )
            return base.copy(executionProofSha256 = proofSha256(base)).also(::validateProof)
        } finally {
            runCatching { connectedHandle?.close() }
            registry.close()
        }
    }

    fun validateProof(proof: SiteProductionDeploymentRealVpsSftpChannelOpenExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(
            proof.status == SiteProductionDeploymentRealVpsSftpChannelOpenExecutionStatus
                .REAL_VPS_SFTP_CHANNEL_OPENED_AND_CLOSED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
        )
        require(proof.durableHandoffConsumed)
        require(proof.executionReceiptConsumed)
        require(proof.freshCredentialResolutionProofValidated)
        require(proof.credentialLeaseMaterialConsumed)
        require(proof.productionNetworkTouched)
        require(proof.hostKeyPinVerifiedAgainstRemote)
        require(proof.productionSshAdapterUsed)
        require(proof.freshSshSessionAcquisitionExecuted)
        require(proof.exactSessionRegistryUsed)
        require(proof.sessionRegistered)
        require(proof.exactRegistryLookupMatched)
        require(proof.sftpChannelOpened && proof.sftpChannelClosed)
        require(!proof.sftpOperationPerformed)
        require(!proof.remoteCommandDispatched)
        require(!proof.remoteReadPerformed)
        require(!proof.mutationPerformed)
        require(proof.sessionClosed)
        require(!proof.coordinatorInvoked)
        require(!proof.exposesDeployUiAction)
        require(proof.realVpsAccessPerformed)
        require(proof.requiresSeparateReadOnlyExecutionBoundary)
        require(proof.requiresSeparateMutationBoundary)
        require(!isLoopbackHost(proof.remoteHostIdentity))
        require(proof.remotePort in 1..65535)
        require(proof.username.isNotBlank())
        require(proof.credentialResolvedAtEpochMillis >= proof.handoffConsumedAtEpochMillis)
        require(proof.executedAtEpochMillis >= proof.credentialResolvedAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.authorizationExpiresAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.freshCredentialAuthorizationExpiresAtEpochMillis)
        require(proof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(proof.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(proof.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(proof.sftpLifecycleProbeImplementation == SiteRemoteSftpChannelLifecycleProbe::class.java.name)
        require(proof.verifiedHostKeySha256 == proof.pinnedHostKeySha256)
        validateHashes(
            proof.authorizationSha256,
            proof.sftpChannelOpenConsumptionReceiptSha256,
            proof.freshCredentialResolutionProofSha256,
            proof.freshCredentialResolutionConsumptionReceiptSha256,
            proof.priorSshExecutionProofSha256,
            proof.priorSshExecutionReceiptSha256,
            proof.serverAccessBindingSha256,
            proof.requestSha256,
            proof.capabilityProfileSha256,
            proof.pinnedHostKeySha256,
            proof.secretReferenceSha256,
            proof.verifiedHostKeySha256,
            proof.executionProofSha256,
        )
        require(proof.executionProofSha256 == proofSha256(proof.copy(executionProofSha256 = ""))) {
            "Real-VPS SFTP channel-open execution proof SHA-256 mismatch"
        }
    }

    private class OneShotLeaseSecretStore(
        private val expectedSecretId: SecretId,
        private val credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
    ) : SecretStore {
        private val readStarted = AtomicBoolean(false)

        override suspend fun read(secretId: SecretId): SecretReadResult {
            if (secretId != expectedSecretId) return SecretReadResult.NotFound
            if (!readStarted.compareAndSet(false, true)) {
                return SecretReadResult.Unavailable("Ephemeral credential lease is single-use")
            }
            val copy = credentialLease.useMaterialOnce { material ->
                material.useBytes { SecretMaterial.fromBytes(it) }
            }
            return SecretReadResult.Found(copy)
        }

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Phase 11.47 lease adapter is read-only")

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.47 lease adapter is read-only")

        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.47 lease adapter does not enumerate secrets")
    }

    private fun secretReferenceSha256(
        serverAccessId: String,
        secretReferenceType: String,
        secretIdValue: String,
    ): String = sha256(buildString {
        append("serverAccessId=").append(serverAccessId).append('\n')
        append("secretReferenceType=").append(secretReferenceType).append('\n')
        append("secretId=").append(secretIdValue).append('\n')
    })

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        secretReferenceType: String,
        secretReferenceSha256: String,
        pinnedHostKeySha256: String,
    ): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("serverId=").append(serverAccess.serverId.value).append('\n')
        append("host=").append(serverAccess.endpoint.host).append('\n')
        append("port=").append(serverAccess.endpoint.port).append('\n')
        append("username=").append(serverAccess.username).append('\n')
        append("secretReferenceType=").append(secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
        append("pinnedHostKeySha256=").append(pinnedHostKeySha256).append('\n')
    })

    private fun proofSha256(proof: SiteProductionDeploymentRealVpsSftpChannelOpenExecutionProof): String =
        sha256(buildString {
            append("phase=11.47\n")
            append("status=").append(proof.status.name).append('\n')
            append("authorizationSha256=").append(proof.authorizationSha256).append('\n')
            append("sftpReceipt=").append(proof.sftpChannelOpenConsumptionReceiptSha256).append('\n')
            append("freshResolutionProof=").append(proof.freshCredentialResolutionProofSha256).append('\n')
            append("freshResolutionReceipt=")
                .append(proof.freshCredentialResolutionConsumptionReceiptSha256).append('\n')
            append("priorSshProof=").append(proof.priorSshExecutionProofSha256).append('\n')
            append("priorSshReceipt=").append(proof.priorSshExecutionReceiptSha256).append('\n')
            append("serverAccessBinding=").append(proof.serverAccessBindingSha256).append('\n')
            append("requestSha256=").append(proof.requestSha256).append('\n')
            append("capabilityProfileSha256=").append(proof.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(proof.serverAccessId).append('\n')
            append("host=").append(proof.remoteHostIdentity).append('\n')
            append("port=").append(proof.remotePort).append('\n')
            append("username=").append(proof.username).append('\n')
            append("pinnedHostKey=").append(proof.pinnedHostKeySha256).append('\n')
            append("secretReferenceType=").append(proof.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(proof.secretReferenceSha256).append('\n')
            append("credentialStore=").append(proof.credentialStoreImplementation).append('\n')
            append("sshFactory=").append(proof.sshConnectionFactoryImplementation).append('\n')
            append("registry=").append(proof.exactSessionRegistryImplementation).append('\n')
            append("sftpProbe=").append(proof.sftpLifecycleProbeImplementation).append('\n')
            append("sessionId=").append(proof.sessionId).append('\n')
            append("ownerId=").append(proof.operationOwnerId).append('\n')
            append("verifiedHostKey=").append(proof.verifiedHostKeySha256).append('\n')
            append("credentialResolvedAt=").append(proof.credentialResolvedAtEpochMillis).append('\n')
            append("handoffConsumedAt=").append(proof.handoffConsumedAtEpochMillis).append('\n')
            append("executedAt=").append(proof.executedAtEpochMillis).append('\n')
            append("authorizationExpiresAt=").append(proof.authorizationExpiresAtEpochMillis).append('\n')
            append("freshCredentialAuthorizationExpiresAt=")
                .append(proof.freshCredentialAuthorizationExpiresAtEpochMillis).append('\n')
            append("executionReceiptConsumed=").append(proof.executionReceiptConsumed).append('\n')
            append("credentialLeaseMaterialConsumed=").append(proof.credentialLeaseMaterialConsumed).append('\n')
            append("productionNetworkTouched=").append(proof.productionNetworkTouched).append('\n')
            append("hostKeyPinVerifiedAgainstRemote=").append(proof.hostKeyPinVerifiedAgainstRemote).append('\n')
            append("sftpChannelOpened=").append(proof.sftpChannelOpened).append('\n')
            append("sftpChannelClosed=").append(proof.sftpChannelClosed).append('\n')
            append("sftpOperationPerformed=").append(proof.sftpOperationPerformed).append('\n')
            append("remoteCommandDispatched=").append(proof.remoteCommandDispatched).append('\n')
            append("remoteReadPerformed=").append(proof.remoteReadPerformed).append('\n')
            append("mutationPerformed=").append(proof.mutationPerformed).append('\n')
            append("sessionClosed=").append(proof.sessionClosed).append('\n')
        })

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.lowercase()
        return normalized == "localhost" || normalized == "::1" || normalized == "[::1]" ||
            normalized.startsWith("127.")
    }

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS SFTP channel-open execution hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

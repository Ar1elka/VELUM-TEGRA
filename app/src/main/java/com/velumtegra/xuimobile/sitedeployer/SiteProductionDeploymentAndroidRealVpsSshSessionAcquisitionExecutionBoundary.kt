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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionUsePort
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Phase 11.44 is the first Site Deployer boundary allowed to contact one real non-loopback VPS.
 *
 * The exact Phase 11.43 durable handoff receipt is mandatory. Before credential material is read or
 * any socket is opened, the receipt itself is durably consumed in a dedicated execution namespace.
 * The already-resolved ephemeral credential lease is then consumed once by the reviewed
 * JschSshConnectionFactory. One pinned-host-key SSH session is acquired, installed into a fresh
 * ExactSessionRegistry, exact-looked-up, removed and closed in the same bounded call.
 *
 * No command, SFTP channel, remote read, mutation, coordinator invocation or deploy UI is reachable
 * from this boundary. A failed connection attempt is not replayable because the durable execution
 * receipt is consumed before the network attempt.
 */
internal object SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,95}$")

    suspend fun acquireSessionOnce(
        receipt: SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionUsePort,
    ): SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionProof {
        SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionHandoffConsumptionBoundary
            .validateReceipt(receipt)
        require(
            receipt.status ==
                SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_SEPARATE_REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
        ) { "Real-VPS SSH execution requires the exact consumed Phase 11.43 receipt" }
        require(receipt.singleUseConsumed)
        require(receipt.requiresLiveRemoteHostKeyVerification)
        require(receipt.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        require(receipt.requiresSeparateSftpChannelOpenBoundary)
        require(receipt.requiresSeparateReadOnlyExecutionBoundary)
        require(receipt.requiresSeparateMutationBoundary)
        require(canonicalId.matches(executionAttemptId)) {
            "Real-VPS SSH execution attempt id must be a canonical 8..96 character identifier"
        }
        require(executedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "Real-VPS SSH execution cannot predate durable handoff consumption"
        }
        require(executedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "Real-VPS SSH authorization window expired before execution"
        }
        require(serverAccess.id.value == receipt.serverAccessId) {
            "Real-VPS SSH execution ServerAccess mismatch"
        }
        require(serverAccess.endpoint.host == receipt.remoteHostIdentity) {
            "Real-VPS SSH execution host identity mismatch"
        }
        require(serverAccess.endpoint.port == receipt.remotePort) {
            "Real-VPS SSH execution port mismatch"
        }
        require(serverAccess.username == receipt.username) {
            "Real-VPS SSH execution username mismatch"
        }
        require(!isLoopbackHost(serverAccess.endpoint.host)) {
            "Phase 11.44 requires the exact reviewed non-loopback real-VPS endpoint"
        }
        require(credentialLease.serverAccessId == receipt.serverAccessId) {
            "Real-VPS SSH execution credential lease ServerAccess mismatch"
        }
        require(credentialLease.secretReferenceType == receipt.secretReferenceType) {
            "Real-VPS SSH execution credential lease auth type mismatch"
        }
        require(credentialLease.secretReferenceSha256 == receipt.secretReferenceSha256) {
            "Real-VPS SSH execution credential lease SecretId hash mismatch"
        }
        require(
            credentialLease.credentialResolutionConsumptionReceiptSha256 ==
                receipt.credentialResolutionConsumptionReceiptSha256,
        ) { "Real-VPS SSH execution credential lease receipt mismatch" }
        require(credentialLease.resolvedAtEpochMillis <= receipt.consumedAtEpochMillis) {
            "Real-VPS SSH handoff predates credential resolution"
        }
        require(executedAtEpochMillis <= credentialLease.authorizationExpiresAtEpochMillis) {
            "Real-VPS SSH execution exceeded credential lease authorization window"
        }
        require(receipt.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(receipt.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(receipt.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == receipt.secretReferenceType) {
            "Real-VPS SSH execution ServerAccess auth type mismatch"
        }
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        require(secretReferenceSha256 == receipt.secretReferenceSha256) {
            "Real-VPS SSH execution raw SecretId binding mismatch"
        }

        val expectedHostKey = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid ->
                throw IllegalArgumentException("Real-VPS SSH pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        require(expectedHostKeySha256 == receipt.pinnedHostKeySha256) {
            "Real-VPS SSH pinned host-key binding drifted"
        }
        require(
            serverAccessBindingSha256(
                serverAccess = serverAccess,
                secretReferenceType = secretReferenceType,
                secretReferenceSha256 = secretReferenceSha256,
                pinnedHostKeySha256 = expectedHostKeySha256,
            ) == receipt.serverAccessBindingSha256,
        ) { "Real-VPS SSH ServerAccess binding drifted after authorization" }

        // Counteraction before action: if execution becomes uncertain after this point, the exact
        // Phase 11.43 receipt cannot be used for another network attempt after process restart.
        require(
            executionUsePort.consumeOnce(receipt.sshSessionAcquisitionConsumptionReceiptSha256),
        ) { "Real-VPS SSH execution receipt was already used or replay fence failed closed" }

        val ownerId = "phase11_44_$executionAttemptId"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId(
            "phase11_44_session_${receipt.authorizationSha256.take(24)}",
        )
        val leaseStore = OneShotLeaseSecretStore(
            expectedSecretId = serverAccess.auth.secretId,
            credentialLease = credentialLease,
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
                    "Real-VPS SSH acquisition failed closed: " +
                        ((connectResult as SshConnectResult.Failed).failure::class.java.simpleName),
                )
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle
                ?: run {
                    connected.handle.close()
                    throw IllegalArgumentException(
                        "Real-VPS SSH acquisition did not return a verified-host-key handle",
                    )
                }
            connectedHandle = verified
            require(verified.isOpen) { "Real-VPS SSH handle is not open after acquisition" }
            require(verified.binding.serverAccessId == serverAccess.id) {
                "Real-VPS SSH binding ServerAccess mismatch"
            }
            require(verified.binding.owner == owner) {
                "Real-VPS SSH binding owner mismatch"
            }
            require(verified.binding.sessionId == deterministicSessionId) {
                "Real-VPS SSH binding SessionId mismatch"
            }
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256) {
                "Real-VPS SSH live host-key verification did not match the reviewed pin"
            }

            require(registry.install(verified) == SessionInstallResult.Installed) {
                "Real-VPS SSH exact registry refused first install"
            }
            require(registry.find(owner, serverAccess.id) === verified) {
                "Real-VPS SSH exact registry lookup did not return acquired handle"
            }

            val sessionIdValue = verified.binding.sessionId.value
            val verifiedHostKeySha256 = verified.verifiedHostKeySha256
            require(
                registry.remove(
                    owner = owner,
                    accessId = serverAccess.id,
                    sessionId = verified.binding.sessionId,
                    close = true,
                ),
            ) { "Real-VPS SSH exact registry failed close/remove" }
            require(registry.size() == 0) {
                "Real-VPS SSH exact registry retained a session after close/remove"
            }
            require(!verified.isOpen) {
                "Real-VPS SSH session remained open after exact registry close/remove"
            }
            connectedHandle = null

            val base = SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionStatus
                    .REAL_VPS_SESSION_ACQUIRED_VERIFIED_REGISTERED_AND_CLOSED,
                durableHandoffConsumed = true,
                executionReceiptConsumed = true,
                credentialLeaseMaterialConsumed = true,
                productionNetworkTouched = true,
                hostKeyPinVerifiedAgainstRemote = true,
                productionSshAdapterUsed = true,
                sshSessionAcquisitionExecuted = true,
                exactSessionRegistryUsed = true,
                sessionRegistered = true,
                exactRegistryLookupMatched = true,
                sessionClosed = true,
                remoteCommandDispatched = false,
                sftpChannelOpened = false,
                remoteReadPerformed = false,
                mutationPerformed = false,
                coordinatorInvoked = false,
                exposesDeployUiAction = false,
                realVpsAccessPerformed = true,
                requiresSeparateSftpChannelOpenBoundary = true,
                requiresSeparateReadOnlyExecutionBoundary = true,
                requiresSeparateMutationBoundary = true,
                authorizationSha256 = receipt.authorizationSha256,
                sshSessionAcquisitionConsumptionReceiptSha256 =
                    receipt.sshSessionAcquisitionConsumptionReceiptSha256,
                resolutionProofSha256 = receipt.resolutionProofSha256,
                credentialResolutionConsumptionReceiptSha256 =
                    receipt.credentialResolutionConsumptionReceiptSha256,
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
                credentialStoreImplementation = receipt.credentialStoreImplementation,
                sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
                exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
                sessionId = sessionIdValue,
                operationOwnerId = ownerId,
                verifiedHostKeySha256 = verifiedHostKeySha256,
                executedAtEpochMillis = executedAtEpochMillis,
                authorizationExpiresAtEpochMillis = receipt.authorizationExpiresAtEpochMillis,
                executionProofSha256 = "",
            )
            return base.copy(executionProofSha256 = proofSha256(base)).also(::validateProof)
        } finally {
            runCatching { connectedHandle?.close() }
            registry.close()
        }
    }

    fun validateProof(proof: SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(
            proof.status ==
                SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionStatus
                    .REAL_VPS_SESSION_ACQUIRED_VERIFIED_REGISTERED_AND_CLOSED,
        )
        require(proof.durableHandoffConsumed)
        require(proof.executionReceiptConsumed)
        require(proof.credentialLeaseMaterialConsumed)
        require(proof.productionNetworkTouched)
        require(proof.hostKeyPinVerifiedAgainstRemote)
        require(proof.productionSshAdapterUsed)
        require(proof.sshSessionAcquisitionExecuted)
        require(proof.exactSessionRegistryUsed)
        require(proof.sessionRegistered)
        require(proof.exactRegistryLookupMatched)
        require(proof.sessionClosed)
        require(!proof.remoteCommandDispatched)
        require(!proof.sftpChannelOpened)
        require(!proof.remoteReadPerformed)
        require(!proof.mutationPerformed)
        require(!proof.coordinatorInvoked)
        require(!proof.exposesDeployUiAction)
        require(proof.realVpsAccessPerformed)
        require(proof.requiresSeparateSftpChannelOpenBoundary)
        require(proof.requiresSeparateReadOnlyExecutionBoundary)
        require(proof.requiresSeparateMutationBoundary)
        require(!isLoopbackHost(proof.remoteHostIdentity))
        require(proof.remotePort in 1..65535)
        require(proof.username.isNotBlank())
        require(proof.executedAtEpochMillis <= proof.authorizationExpiresAtEpochMillis)
        require(proof.secretReferenceType == "password" || proof.secretReferenceType == "private-key")
        require(proof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(proof.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(proof.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(proof.verifiedHostKeySha256 == proof.pinnedHostKeySha256)
        validateHashes(
            proof.authorizationSha256,
            proof.sshSessionAcquisitionConsumptionReceiptSha256,
            proof.resolutionProofSha256,
            proof.credentialResolutionConsumptionReceiptSha256,
            proof.serverAccessBindingSha256,
            proof.requestSha256,
            proof.capabilityProfileSha256,
            proof.pinnedHostKeySha256,
            proof.secretReferenceSha256,
            proof.verifiedHostKeySha256,
            proof.executionProofSha256,
        )
        require(
            proof.executionProofSha256 == proofSha256(proof.copy(executionProofSha256 = "")),
        ) { "Real-VPS SSH execution proof SHA-256 mismatch" }
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
            val transportOwnedCopy = credentialLease.useMaterialOnce { material ->
                material.useBytes { bytes -> SecretMaterial.fromBytes(bytes) }
            }
            return SecretReadResult.Found(transportOwnedCopy)
        }

        override suspend fun create(
            secretId: SecretId,
            material: SecretMaterial,
        ): SecretCreateResult = SecretCreateResult.StorageFailure(
            "Phase 11.44 lease adapter is read-only",
        )

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.44 lease adapter is read-only")

        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.44 lease adapter does not enumerate secrets")
    }

    private fun secretReferenceSha256(
        serverAccessId: String,
        secretReferenceType: String,
        secretIdValue: String,
    ): String = sha256(
        buildString {
            append("serverAccessId=").append(serverAccessId).append('\n')
            append("secretReferenceType=").append(secretReferenceType).append('\n')
            append("secretId=").append(secretIdValue).append('\n')
        },
    )

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        secretReferenceType: String,
        secretReferenceSha256: String,
        pinnedHostKeySha256: String,
    ): String = sha256(
        buildString {
            append("serverAccessId=").append(serverAccess.id.value).append('\n')
            append("serverId=").append(serverAccess.serverId.value).append('\n')
            append("host=").append(serverAccess.endpoint.host).append('\n')
            append("port=").append(serverAccess.endpoint.port).append('\n')
            append("username=").append(serverAccess.username).append('\n')
            append("secretReferenceType=").append(secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
            append("pinnedHostKeySha256=").append(pinnedHostKeySha256).append('\n')
        },
    )

    private fun proofSha256(
        proof: SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionProof,
    ): String = sha256(
        buildString {
            append("phase=11.44\n")
            append("contractVersion=").append(proof.contractVersion).append('\n')
            append("status=").append(proof.status.name).append('\n')
            append("durableHandoffConsumed=").append(proof.durableHandoffConsumed).append('\n')
            append("executionReceiptConsumed=").append(proof.executionReceiptConsumed).append('\n')
            append("credentialLeaseMaterialConsumed=").append(proof.credentialLeaseMaterialConsumed).append('\n')
            append("productionNetworkTouched=").append(proof.productionNetworkTouched).append('\n')
            append("hostKeyPinVerifiedAgainstRemote=").append(proof.hostKeyPinVerifiedAgainstRemote).append('\n')
            append("productionSshAdapterUsed=").append(proof.productionSshAdapterUsed).append('\n')
            append("sshSessionAcquisitionExecuted=").append(proof.sshSessionAcquisitionExecuted).append('\n')
            append("exactSessionRegistryUsed=").append(proof.exactSessionRegistryUsed).append('\n')
            append("sessionRegistered=").append(proof.sessionRegistered).append('\n')
            append("exactRegistryLookupMatched=").append(proof.exactRegistryLookupMatched).append('\n')
            append("sessionClosed=").append(proof.sessionClosed).append('\n')
            append("remoteCommandDispatched=").append(proof.remoteCommandDispatched).append('\n')
            append("sftpChannelOpened=").append(proof.sftpChannelOpened).append('\n')
            append("remoteReadPerformed=").append(proof.remoteReadPerformed).append('\n')
            append("mutationPerformed=").append(proof.mutationPerformed).append('\n')
            append("coordinatorInvoked=").append(proof.coordinatorInvoked).append('\n')
            append("exposesDeployUiAction=").append(proof.exposesDeployUiAction).append('\n')
            append("realVpsAccessPerformed=").append(proof.realVpsAccessPerformed).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(proof.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("requiresSeparateReadOnlyExecutionBoundary=")
                .append(proof.requiresSeparateReadOnlyExecutionBoundary).append('\n')
            append("requiresSeparateMutationBoundary=")
                .append(proof.requiresSeparateMutationBoundary).append('\n')
            append("authorizationSha256=").append(proof.authorizationSha256).append('\n')
            append("sshSessionAcquisitionConsumptionReceiptSha256=")
                .append(proof.sshSessionAcquisitionConsumptionReceiptSha256).append('\n')
            append("resolutionProofSha256=").append(proof.resolutionProofSha256).append('\n')
            append("credentialResolutionConsumptionReceiptSha256=")
                .append(proof.credentialResolutionConsumptionReceiptSha256).append('\n')
            append("serverAccessBindingSha256=").append(proof.serverAccessBindingSha256).append('\n')
            append("requestSha256=").append(proof.requestSha256).append('\n')
            append("capabilityProfileSha256=").append(proof.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(proof.serverAccessId).append('\n')
            append("remoteHostIdentity=").append(proof.remoteHostIdentity).append('\n')
            append("remotePort=").append(proof.remotePort).append('\n')
            append("username=").append(proof.username).append('\n')
            append("pinnedHostKeySha256=").append(proof.pinnedHostKeySha256).append('\n')
            append("secretReferenceType=").append(proof.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(proof.secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(proof.credentialStoreImplementation).append('\n')
            append("sshConnectionFactoryImplementation=")
                .append(proof.sshConnectionFactoryImplementation).append('\n')
            append("exactSessionRegistryImplementation=")
                .append(proof.exactSessionRegistryImplementation).append('\n')
            append("sessionId=").append(proof.sessionId).append('\n')
            append("operationOwnerId=").append(proof.operationOwnerId).append('\n')
            append("verifiedHostKeySha256=").append(proof.verifiedHostKeySha256).append('\n')
            append("executedAtEpochMillis=").append(proof.executedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=")
                .append(proof.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.lowercase()
        return normalized == "localhost" ||
            normalized == "::1" ||
            normalized == "[::1]" ||
            normalized.startsWith("127.")
    }

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS SSH execution hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

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
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Phase 11.33 is the first actual SSH-session acquisition boundary for Site Deployer.
 *
 * Safety scope is deliberately narrow:
 * - the exact Phase 11.32 durable receipt is mandatory;
 * - only adb-reverse loopback fixture endpoints are accepted;
 * - the already-resolved in-memory credential lease is consumed exactly once;
 * - the reviewed JschSshConnectionFactory and ExactSessionRegistry are used directly;
 * - one session is acquired, installed, exact-looked-up, removed and closed;
 * - no exec command, SFTP channel, coordinator call, deploy UI action or real-VPS access is possible here.
 */
internal object SiteProductionDeploymentAndroidSshSessionAcquisitionExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val FIXTURE_LOOPBACK_HOST: String = "127.0.0.1"

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun acquireFixtureSessionOnce(
        receipt: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentSshSessionAcquisitionExecutionProof {
        SiteProductionDeploymentAndroidSshSessionAcquisitionHandoffConsumptionBoundary
            .validateReceipt(receipt)
        require(
            receipt.status ==
                SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_SEPARATE_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
        ) { "SSH-session acquisition execution requires the exact consumed Phase 11.32 receipt" }
        require(receipt.singleUseConsumed) {
            "SSH-session acquisition execution requires durable one-shot handoff consumption"
        }
        require(receipt.requiresSeparateSshSessionAcquisitionExecutionBoundary) {
            "Phase 11.32 receipt does not admit this execution boundary"
        }
        require(serverAccess.id.value == receipt.serverAccessId) {
            "SSH-session acquisition execution ServerAccess mismatch"
        }
        require(serverAccess.endpoint.host == receipt.remoteHostIdentity) {
            "SSH-session acquisition execution remote host mismatch"
        }
        require(serverAccess.endpoint.host == FIXTURE_LOOPBACK_HOST) {
            "Phase 11.33 accepts only the adb-reverse loopback fixture endpoint"
        }
        require(serverAccess.endpoint.port in 1..65535) {
            "SSH-session acquisition fixture port is invalid"
        }
        require(credentialLease.serverAccessId == receipt.serverAccessId) {
            "SSH-session acquisition credential lease ServerAccess mismatch"
        }
        require(credentialLease.secretReferenceType == receipt.secretReferenceType) {
            "SSH-session acquisition credential lease auth type mismatch"
        }
        require(credentialLease.secretReferenceSha256 == receipt.secretReferenceSha256) {
            "SSH-session acquisition credential lease SecretId hash mismatch"
        }
        require(credentialLease.resolvedAtEpochMillis <= receipt.consumedAtEpochMillis) {
            "SSH-session acquisition handoff predates credential resolution"
        }
        require(executedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "SSH-session acquisition execution cannot predate durable handoff consumption"
        }
        require(executedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "SSH-session acquisition execution exceeded Phase 11.31 authorization window"
        }
        require(executedAtEpochMillis <= credentialLease.authorizationExpiresAtEpochMillis) {
            "SSH-session acquisition execution exceeded credential lease authorization window"
        }
        require(canonicalId.matches(executionAttemptId)) {
            "SSH-session acquisition execution attempt id must be a canonical 8..128 character identifier"
        }
        require(receipt.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name) {
            "SSH-session acquisition execution JSch implementation identity mismatch"
        }
        require(receipt.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name) {
            "SSH-session acquisition execution registry implementation identity mismatch"
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == receipt.secretReferenceType) {
            "SSH-session acquisition execution ServerAccess auth type mismatch"
        }
        require(
            secretReferenceSha256(
                serverAccessId = serverAccess.id.value,
                secretReferenceType = secretReferenceType,
                secretIdValue = serverAccess.auth.secretId.value,
            ) == receipt.secretReferenceSha256,
        ) { "SSH-session acquisition execution raw SecretId binding mismatch" }

        val expectedHostKey = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid ->
                throw IllegalArgumentException("SSH-session acquisition pinned host key is invalid")
        }

        val ownerId = "phase11_33_$executionAttemptId"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId(
            "phase11_33_session_${receipt.authorizationSha256.take(24)}",
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
                    "SSH-session fixture acquisition failed: " +
                        ((connectResult as SshConnectResult.Failed).failure::class.java.simpleName),
                )
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle
                ?: run {
                    connected.handle.close()
                    throw IllegalArgumentException(
                        "SSH-session acquisition did not return a verified-host-key session handle",
                    )
                }
            connectedHandle = verified
            require(verified.isOpen) { "SSH-session fixture handle is not open after acquisition" }
            require(verified.binding.serverAccessId == serverAccess.id) {
                "SSH-session fixture binding ServerAccess mismatch"
            }
            require(verified.binding.owner == owner) {
                "SSH-session fixture binding owner mismatch"
            }
            require(verified.binding.sessionId == deterministicSessionId) {
                "SSH-session fixture binding SessionId mismatch"
            }
            require(verified.verifiedHostKeySha256 == expectedHostKey.asHexSha256()) {
                "SSH-session fixture verified host-key digest mismatch"
            }

            require(registry.install(verified) == SessionInstallResult.Installed) {
                "SSH-session fixture exact registry refused first install"
            }
            require(registry.find(owner, serverAccess.id) === verified) {
                "SSH-session fixture exact registry lookup did not return acquired handle"
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
            ) { "SSH-session fixture exact registry failed close/remove" }
            require(registry.size() == 0) {
                "SSH-session fixture exact registry retained a session after close/remove"
            }
            require(!verified.isOpen) {
                "SSH-session fixture remained open after exact registry close/remove"
            }
            connectedHandle = null

            val base = SiteProductionDeploymentSshSessionAcquisitionExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentSshSessionAcquisitionExecutionStatus
                    .FIXTURE_SESSION_ACQUIRED_REGISTERED_AND_CLOSED,
                fixtureEndpointRequired = true,
                credentialLeaseMaterialConsumed = true,
                productionSshAdapterUsed = true,
                sshSessionAcquisitionExecuted = true,
                exactSessionRegistryUsed = true,
                sessionRegistered = true,
                exactRegistryLookupMatched = true,
                sessionClosed = true,
                remoteCommandDispatched = false,
                sftpChannelOpened = false,
                coordinatorInvoked = false,
                exposesDeployUiAction = false,
                realVpsAccessAllowed = false,
                requiresSeparateSftpChannelOpenBoundary = true,
                requiresSeparateCoordinatorInvocationBoundary = true,
                authorizationSha256 = receipt.authorizationSha256,
                sshSessionAcquisitionConsumptionReceiptSha256 =
                    receipt.sshSessionAcquisitionConsumptionReceiptSha256,
                resolutionProofSha256 = receipt.resolutionProofSha256,
                serverAccessBindingSha256 = receipt.serverAccessBindingSha256,
                serverAccessId = receipt.serverAccessId,
                remoteHostIdentity = serverAccess.endpoint.host,
                remotePort = serverAccess.endpoint.port,
                secretReferenceType = receipt.secretReferenceType,
                secretReferenceSha256 = receipt.secretReferenceSha256,
                sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
                exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
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

    fun validateProof(proof: SiteProductionDeploymentSshSessionAcquisitionExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(
            proof.status ==
                SiteProductionDeploymentSshSessionAcquisitionExecutionStatus
                    .FIXTURE_SESSION_ACQUIRED_REGISTERED_AND_CLOSED,
        )
        require(proof.fixtureEndpointRequired)
        require(proof.credentialLeaseMaterialConsumed)
        require(proof.productionSshAdapterUsed)
        require(proof.sshSessionAcquisitionExecuted)
        require(proof.exactSessionRegistryUsed)
        require(proof.sessionRegistered)
        require(proof.exactRegistryLookupMatched)
        require(proof.sessionClosed)
        require(!proof.remoteCommandDispatched)
        require(!proof.sftpChannelOpened)
        require(!proof.coordinatorInvoked)
        require(!proof.exposesDeployUiAction)
        require(!proof.realVpsAccessAllowed)
        require(proof.requiresSeparateSftpChannelOpenBoundary)
        require(proof.requiresSeparateCoordinatorInvocationBoundary)
        require(proof.remoteHostIdentity == FIXTURE_LOOPBACK_HOST)
        require(proof.remotePort in 1..65535)
        require(proof.secretReferenceType == "password" || proof.secretReferenceType == "private-key")
        require(proof.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(proof.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        validateHashes(
            proof.authorizationSha256,
            proof.sshSessionAcquisitionConsumptionReceiptSha256,
            proof.resolutionProofSha256,
            proof.serverAccessBindingSha256,
            proof.secretReferenceSha256,
            proof.verifiedHostKeySha256,
            proof.executionProofSha256,
        )
        require(
            proof.executionProofSha256 ==
                proofSha256(proof.copy(executionProofSha256 = "")),
        ) { "SSH-session acquisition execution proof SHA-256 mismatch" }
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
            "Phase 11.33 lease adapter is read-only",
        )

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.33 lease adapter is read-only")

        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.33 lease adapter does not enumerate secrets")
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

    private fun proofSha256(
        proof: SiteProductionDeploymentSshSessionAcquisitionExecutionProof,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(proof.contractVersion).append('\n')
            append("status=").append(proof.status.name).append('\n')
            append("fixtureEndpointRequired=").append(proof.fixtureEndpointRequired).append('\n')
            append("credentialLeaseMaterialConsumed=").append(proof.credentialLeaseMaterialConsumed).append('\n')
            append("productionSshAdapterUsed=").append(proof.productionSshAdapterUsed).append('\n')
            append("sshSessionAcquisitionExecuted=").append(proof.sshSessionAcquisitionExecuted).append('\n')
            append("exactSessionRegistryUsed=").append(proof.exactSessionRegistryUsed).append('\n')
            append("sessionRegistered=").append(proof.sessionRegistered).append('\n')
            append("exactRegistryLookupMatched=").append(proof.exactRegistryLookupMatched).append('\n')
            append("sessionClosed=").append(proof.sessionClosed).append('\n')
            append("remoteCommandDispatched=").append(proof.remoteCommandDispatched).append('\n')
            append("sftpChannelOpened=").append(proof.sftpChannelOpened).append('\n')
            append("coordinatorInvoked=").append(proof.coordinatorInvoked).append('\n')
            append("exposesDeployUiAction=").append(proof.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(proof.realVpsAccessAllowed).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(proof.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("requiresSeparateCoordinatorInvocationBoundary=")
                .append(proof.requiresSeparateCoordinatorInvocationBoundary).append('\n')
            append("authorizationSha256=").append(proof.authorizationSha256).append('\n')
            append("sshSessionAcquisitionConsumptionReceiptSha256=")
                .append(proof.sshSessionAcquisitionConsumptionReceiptSha256).append('\n')
            append("resolutionProofSha256=").append(proof.resolutionProofSha256).append('\n')
            append("serverAccessBindingSha256=").append(proof.serverAccessBindingSha256).append('\n')
            append("serverAccessId=").append(proof.serverAccessId).append('\n')
            append("remoteHostIdentity=").append(proof.remoteHostIdentity).append('\n')
            append("remotePort=").append(proof.remotePort).append('\n')
            append("secretReferenceType=").append(proof.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(proof.secretReferenceSha256).append('\n')
            append("sshConnectionFactoryImplementation=")
                .append(proof.sshConnectionFactoryImplementation).append('\n')
            append("exactSessionRegistryImplementation=")
                .append(proof.exactSessionRegistryImplementation).append('\n')
            append("sessionId=").append(proof.sessionId).append('\n')
            append("operationOwnerId=").append(proof.operationOwnerId).append('\n')
            append("verifiedHostKeySha256=").append(proof.verifiedHostKeySha256).append('\n')
            append("executedAtEpochMillis=").append(proof.executedAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "SSH-session acquisition execution hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

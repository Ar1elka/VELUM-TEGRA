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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteWebServingNginxReloadSshAdapter
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/** Phase 11.61 performs one durable-gated nginx reload and no config mutation. */
internal object SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun executeOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        activationProof: SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionProof,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort,
    ): SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionProof {
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingConfigActivationExecutionBoundary.validate(activationPlan)
        SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary.validateProof(activationProof)
        SiteWebServingNginxReloadExecutionBoundary.validateAgainst(reloadPlan, activationPlan, publicationPlan)
        require(activationProof.activationPlanSha256 == activationPlan.activationPlanSha256)
        require(activationProof.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(activationProof.exactConfigPathPresentAfterActivation)
        require(activationProof.exactConfigSha256Verified)
        require(activationProof.nginxSyntaxValidationPassed)
        require(activationProof.listenerStillFreeAfterActivation)
        require(!activationProof.webServerReloadPerformed)
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(freshResolutionProof)
        require(publicationPlan.remoteHostIdentity == serverAccess.endpoint.host)
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

        val expectedHostKey = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid -> throw IllegalArgumentException("Phase 11.61 pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        val bindingSha256 = serverAccessBindingSha256(serverAccess, secretReferenceType, secretReferenceSha256, expectedHostKeySha256)
        require(freshResolutionProof.serverAccessBindingSha256 == bindingSha256)

        val ownerId = "phase11_61_${reloadPlan.reloadPlanSha256.take(24)}"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId("phase11_61_session_${reloadPlan.reloadPlanSha256.take(24)}")
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
                    commandExecutionTimeout = Duration.ofSeconds(12),
                    stdoutCaptureLimitBytes = 32 * 1024,
                    stderrCaptureLimitBytes = 64 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Phase 11.61 fresh SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close(); throw IllegalArgumentException("Phase 11.61 missing verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256)
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)

            val adapter = SiteWebServingNginxReloadSshAdapter()
            val ready = adapter.verifyBeforeReload(reloadPlan, publicationPlan, serverAccess, verified)
            require(ready.verifiedHostKeySha256 == expectedHostKeySha256)
            require(executionUsePort.consumeOnce(reloadPlan.reloadPlanSha256)) {
                "Phase 11.61 durable pre-reload checkpoint/replay fence rejected reload plan"
            }
            val observation = adapter.reloadOnce(
                reloadPlan = reloadPlan,
                publicationPlan = publicationPlan,
                access = serverAccess,
                session = verified,
                durablePreReloadCheckpointRecorded = true,
                priorCommandCount = ready.remoteCommandCount,
            )
            val sessionIdValue = verified.binding.sessionId.value
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0 && !verified.isOpen)
            connectedHandle = null

            val base = SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionStatus.NGINX_RELOADED_ONCE_EXACT_CONFIG_PRESERVED_EXPECTED_LISTENER_LIVE,
                reloadPlanSha256 = reloadPlan.reloadPlanSha256,
                activationPlanSha256 = activationPlan.activationPlanSha256,
                activationExecutionProofSha256 = activationProof.executionProofSha256,
                publicationPlanSha256 = publicationPlan.publicationPlanSha256,
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
                sessionId = sessionIdValue,
                operationOwnerId = ownerId,
                remoteCommandCount = observation.remoteCommandCount,
                successfulActivationProofValidated = true,
                exactConfigSha256VerifiedBeforeReload = observation.exactConfigSha256VerifiedBeforeReload,
                nginxSyntaxValidationPassedBeforeReload = observation.nginxSyntaxValidationPassedBeforeReload,
                listenerFreeBeforeReload = observation.listenerFreeBeforeReload,
                durablePreReloadCheckpointRecorded = observation.durablePreReloadCheckpointRecorded,
                nginxReloadPerformed = observation.nginxReloadPerformed,
                exactConfigSha256VerifiedAfterReload = observation.exactConfigSha256VerifiedAfterReload,
                nginxMasterRunningAfterReload = observation.nginxMasterRunningAfterReload,
                expectedListenerLiveAfterReload = observation.expectedListenerLiveAfterReload,
                credentialLeaseMaterialConsumed = true,
                productionNetworkTouched = true,
                hostKeyPinVerifiedAgainstRemote = true,
                exactSessionRegistryUsed = true,
                arbitraryCommandAccepted = observation.arbitraryCommandAccepted,
                configMutationPerformed = observation.configMutationPerformed,
                privateKeyContentReadPerformed = false,
                dnsMutationPerformed = observation.dnsMutationPerformed,
                firewallMutationPerformed = observation.firewallMutationPerformed,
                packageInstallPerformed = observation.packageInstallPerformed,
                automaticRetryPerformed = observation.automaticRetryPerformed,
                sessionClosed = true,
                coordinatorInvoked = false,
                exposesDeployUiAction = false,
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

    fun validateProof(proof: SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(proof.status == SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionStatus.NGINX_RELOADED_ONCE_EXACT_CONFIG_PRESERVED_EXPECTED_LISTENER_LIVE)
        require(proof.successfulActivationProofValidated)
        require(proof.exactConfigSha256VerifiedBeforeReload && proof.nginxSyntaxValidationPassedBeforeReload)
        require(proof.listenerFreeBeforeReload && proof.durablePreReloadCheckpointRecorded)
        require(proof.nginxReloadPerformed)
        require(proof.exactConfigSha256VerifiedAfterReload && proof.nginxMasterRunningAfterReload)
        require(proof.expectedListenerLiveAfterReload)
        require(proof.remoteCommandCount == 3)
        require(proof.credentialLeaseMaterialConsumed && proof.productionNetworkTouched)
        require(proof.hostKeyPinVerifiedAgainstRemote && proof.exactSessionRegistryUsed && proof.sessionClosed)
        require(!proof.arbitraryCommandAccepted && !proof.configMutationPerformed && !proof.privateKeyContentReadPerformed)
        require(!proof.dnsMutationPerformed && !proof.firewallMutationPerformed && !proof.packageInstallPerformed)
        require(!proof.automaticRetryPerformed && !proof.coordinatorInvoked && !proof.exposesDeployUiAction)
        require(proof.executedAtEpochMillis >= proof.credentialResolvedAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.freshCredentialAuthorizationExpiresAtEpochMillis)
        listOf(proof.reloadPlanSha256, proof.activationPlanSha256, proof.activationExecutionProofSha256,
            proof.publicationPlanSha256, proof.freshCredentialResolutionProofSha256,
            proof.freshCredentialResolutionConsumptionReceiptSha256, proof.serverAccessBindingSha256,
            proof.pinnedHostKeySha256, proof.secretReferenceSha256, proof.executionProofSha256)
            .forEach { require(sha256.matches(it)) }
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
        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult = SecretCreateResult.StorageFailure("Phase 11.61 lease adapter is read-only")
        override suspend fun delete(secretId: SecretId): SecretDeleteResult = SecretDeleteResult.StorageFailure("Phase 11.61 lease adapter is read-only")
        override suspend fun listIds(): SecretListResult = SecretListResult.StorageFailure("Phase 11.61 lease adapter does not enumerate secrets")
    }

    private fun secretReferenceSha256(serverAccessId: String, type: String, secretId: String): String = digest(buildString {
        append("serverAccessId=").append(serverAccessId).append('\n')
        append("secretReferenceType=").append(type).append('\n')
        append("secretId=").append(secretId).append('\n')
    })

    private fun serverAccessBindingSha256(serverAccess: ServerAccess, type: String, secretSha: String, pinSha: String): String = digest(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("serverId=").append(serverAccess.serverId.value).append('\n')
        append("host=").append(serverAccess.endpoint.host).append('\n')
        append("port=").append(serverAccess.endpoint.port).append('\n')
        append("username=").append(serverAccess.username).append('\n')
        append("secretReferenceType=").append(type).append('\n')
        append("secretReferenceSha256=").append(secretSha).append('\n')
        append("pinnedHostKeySha256=").append(pinSha).append('\n')
    })

    private fun proofSha256(proof: SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionProof): String = digest(buildString {
        append("phase=11.61\n")
        append("contractVersion=").append(proof.contractVersion).append('\n')
        append("status=").append(proof.status.name).append('\n')
        append("reloadPlan=").append(proof.reloadPlanSha256).append('\n')
        append("activationPlan=").append(proof.activationPlanSha256).append('\n')
        append("activationProof=").append(proof.activationExecutionProofSha256).append('\n')
        append("publicationPlan=").append(proof.publicationPlanSha256).append('\n')
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
        append("sessionId=").append(proof.sessionId).append('\n')
        append("ownerId=").append(proof.operationOwnerId).append('\n')
        append("remoteCommandCount=").append(proof.remoteCommandCount).append('\n')
        append("successfulActivationProofValidated=").append(proof.successfulActivationProofValidated).append('\n')
        append("exactConfigSha256VerifiedBeforeReload=").append(proof.exactConfigSha256VerifiedBeforeReload).append('\n')
        append("nginxSyntaxValidationPassedBeforeReload=").append(proof.nginxSyntaxValidationPassedBeforeReload).append('\n')
        append("listenerFreeBeforeReload=").append(proof.listenerFreeBeforeReload).append('\n')
        append("durablePreReloadCheckpointRecorded=").append(proof.durablePreReloadCheckpointRecorded).append('\n')
        append("nginxReloadPerformed=").append(proof.nginxReloadPerformed).append('\n')
        append("exactConfigSha256VerifiedAfterReload=").append(proof.exactConfigSha256VerifiedAfterReload).append('\n')
        append("nginxMasterRunningAfterReload=").append(proof.nginxMasterRunningAfterReload).append('\n')
        append("expectedListenerLiveAfterReload=").append(proof.expectedListenerLiveAfterReload).append('\n')
        append("credentialLeaseMaterialConsumed=").append(proof.credentialLeaseMaterialConsumed).append('\n')
        append("productionNetworkTouched=").append(proof.productionNetworkTouched).append('\n')
        append("hostKeyPinVerifiedAgainstRemote=").append(proof.hostKeyPinVerifiedAgainstRemote).append('\n')
        append("exactSessionRegistryUsed=").append(proof.exactSessionRegistryUsed).append('\n')
        append("arbitraryCommandAccepted=").append(proof.arbitraryCommandAccepted).append('\n')
        append("configMutationPerformed=").append(proof.configMutationPerformed).append('\n')
        append("privateKeyContentReadPerformed=").append(proof.privateKeyContentReadPerformed).append('\n')
        append("dnsMutationPerformed=").append(proof.dnsMutationPerformed).append('\n')
        append("firewallMutationPerformed=").append(proof.firewallMutationPerformed).append('\n')
        append("packageInstallPerformed=").append(proof.packageInstallPerformed).append('\n')
        append("automaticRetryPerformed=").append(proof.automaticRetryPerformed).append('\n')
        append("sessionClosed=").append(proof.sessionClosed).append('\n')
        append("coordinatorInvoked=").append(proof.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(proof.exposesDeployUiAction).append('\n')
        append("credentialResolvedAt=").append(proof.credentialResolvedAtEpochMillis).append('\n')
        append("executedAt=").append(proof.executedAtEpochMillis).append('\n')
        append("authorizationExpiresAt=").append(proof.freshCredentialAuthorizationExpiresAtEpochMillis).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray()).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.trim().lowercase()
        return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
    }
}

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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparation
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteWebServingConfigActivationSshAdapter
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/** Phase 11.60 performs one exact config activation and never reloads nginx. */
internal object SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun executeOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
        mutationPreparation: SiteWebServingConfigMutationPreparation,
        stagingSyntaxPlan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        stagingSyntaxProof: SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionProof,
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort,
    ): SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionProof {
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingReadOnlyPreflightBoundary.validateReport(readOnlyPreflight)
        SiteWebServingConfigMutationPreparationBoundary.validateAgainst(mutationPreparation, publicationPlan, readOnlyPreflight)
        SiteWebServingConfigStagingSyntaxExecutionBoundary.validateAgainst(
            stagingSyntaxPlan,
            mutationPreparation,
            publicationPlan,
            readOnlyPreflight,
        )
        SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary.validateProof(stagingSyntaxProof)
        SiteWebServingConfigActivationExecutionBoundary.validateAgainst(
            activationPlan,
            mutationPreparation,
            stagingSyntaxPlan,
            publicationPlan,
            readOnlyPreflight,
        )
        require(stagingSyntaxProof.executionPlanSha256 == stagingSyntaxPlan.executionPlanSha256)
        require(stagingSyntaxProof.mutationPreparationSha256 == mutationPreparation.mutationPreparationSha256)
        require(stagingSyntaxProof.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(stagingSyntaxProof.readOnlyPreflightSha256 == readOnlyPreflight.preflightSha256)
        require(stagingSyntaxProof.nginxSyntaxValidationPassed)
        require(stagingSyntaxProof.exactConfigPathAbsentAfterValidation)
        require(stagingSyntaxProof.stagingConfigAbsentAfterCleanup)
        require(stagingSyntaxProof.listenerStillFreeAfterValidation)
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(freshResolutionProof)
        require(publicationPlan.remoteHostIdentity == serverAccess.endpoint.host)
        require(!isLoopbackHost(serverAccess.endpoint.host))
        require(serverAccess.endpoint.port in 1..65535)
        require(canonicalId.matches(executionAttemptId))
        require(executedAtEpochMillis >= freshResolutionProof.resolvedAtEpochMillis)
        require(executedAtEpochMillis <= freshResolutionProof.authorizationExpiresAtEpochMillis)
        require(
            freshResolutionProof.status ==
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.RESOLVED_TO_EPHEMERAL_LEASE,
        )
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
        require(
            freshCredentialLease.credentialResolutionConsumptionReceiptSha256 ==
                freshResolutionProof.credentialResolutionConsumptionReceiptSha256,
        )
        require(freshCredentialLease.resolvedAtEpochMillis == freshResolutionProof.resolvedAtEpochMillis)
        require(freshCredentialLease.authorizationExpiresAtEpochMillis == freshResolutionProof.authorizationExpiresAtEpochMillis)

        val expectedHostKey = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid -> throw IllegalArgumentException("Phase 11.60 pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        val bindingSha256 = serverAccessBindingSha256(
            serverAccess,
            secretReferenceType,
            secretReferenceSha256,
            expectedHostKeySha256,
        )
        require(freshResolutionProof.serverAccessBindingSha256 == bindingSha256)

        val ownerId = "phase11_60_${activationPlan.activationPlanSha256.take(24)}"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId("phase11_60_session_${activationPlan.activationPlanSha256.take(24)}")
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
                    commandExecutionTimeout = Duration.ofSeconds(8),
                    stdoutCaptureLimitBytes = 32 * 1024,
                    stderrCaptureLimitBytes = 64 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Phase 11.60 fresh SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException("Phase 11.60 missing verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256) {
                "Phase 11.60 live host-key verification does not match reviewed pin"
            }
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)

            val adapter = SiteWebServingConfigActivationSshAdapter()
            val ready = adapter.verifyBeforeActivation(
                activationPlan = activationPlan,
                publicationPlan = publicationPlan,
                access = serverAccess,
                session = verified,
            )
            require(ready.verifiedHostKeySha256 == expectedHostKeySha256)
            require(executionUsePort.consumeOnce(activationPlan.activationPlanSha256)) {
                "Phase 11.60 durable preactivation checkpoint/replay fence rejected activation plan"
            }
            val observation = adapter.activateOnce(
                activationPlan = activationPlan,
                publicationPlan = publicationPlan,
                access = serverAccess,
                session = verified,
                durablePreactivationCheckpointRecorded = true,
                priorCommandCount = ready.remoteCommandCount,
            )

            val sessionIdValue = verified.binding.sessionId.value
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0 && !verified.isOpen)
            connectedHandle = null

            val base = SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionStatus
                    .EXACT_CONFIG_ACTIVATED_SHA_VERIFIED_SYNTAX_VALIDATED_WITHOUT_RELOAD,
                activationPlanSha256 = activationPlan.activationPlanSha256,
                stagingSyntaxExecutionPlanSha256 = stagingSyntaxPlan.executionPlanSha256,
                stagingSyntaxExecutionProofSha256 = stagingSyntaxProof.executionProofSha256,
                mutationPreparationSha256 = mutationPreparation.mutationPreparationSha256,
                publicationPlanSha256 = publicationPlan.publicationPlanSha256,
                readOnlyPreflightSha256 = readOnlyPreflight.preflightSha256,
                freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
                freshCredentialResolutionConsumptionReceiptSha256 =
                    freshResolutionProof.credentialResolutionConsumptionReceiptSha256,
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
                successfulStagingSyntaxProofValidated = true,
                durablePreactivationCheckpointRecorded = observation.durablePreactivationCheckpointRecorded,
                credentialLeaseMaterialConsumed = true,
                productionNetworkTouched = true,
                hostKeyPinVerifiedAgainstRemote = true,
                exactSessionRegistryUsed = true,
                mutationOperationPerformed = true,
                stagingConfigWritePerformed = observation.stagingWritePerformed,
                stagingConfigSha256Verified = observation.stagingSha256Verified,
                exactConfigActivationPerformed = observation.exactConfigActivationPerformed,
                exactConfigSha256Verified = observation.exactConfigSha256Verified,
                nginxSyntaxValidationPassed = observation.nginxSyntaxValidationPassed,
                exactConfigPathPresentAfterActivation = observation.exactConfigPathPresentAfterActivation,
                stagingConfigAbsentAfterActivation = observation.stagingConfigAbsentAfterActivation,
                listenerStillFreeAfterActivation = observation.listenerStillFreeAfterActivation,
                rollbackToAbsentPerformed = observation.rollbackToAbsentPerformed,
                arbitraryCommandAccepted = observation.arbitraryCommandAccepted,
                privateKeyContentReadPerformed = false,
                webServerReloadPerformed = observation.webServerReloadPerformed,
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

    fun validateProof(proof: SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(
            proof.status == SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionStatus
                .EXACT_CONFIG_ACTIVATED_SHA_VERIFIED_SYNTAX_VALIDATED_WITHOUT_RELOAD,
        )
        require(proof.successfulStagingSyntaxProofValidated)
        require(proof.durablePreactivationCheckpointRecorded)
        require(proof.credentialLeaseMaterialConsumed)
        require(proof.productionNetworkTouched && proof.hostKeyPinVerifiedAgainstRemote)
        require(proof.exactSessionRegistryUsed && proof.sessionClosed)
        require(proof.remoteCommandCount == 7)
        require(proof.mutationOperationPerformed)
        require(proof.stagingConfigWritePerformed && proof.stagingConfigSha256Verified)
        require(proof.exactConfigActivationPerformed && proof.exactConfigSha256Verified)
        require(proof.nginxSyntaxValidationPassed)
        require(proof.exactConfigPathPresentAfterActivation)
        require(proof.stagingConfigAbsentAfterActivation)
        require(proof.listenerStillFreeAfterActivation)
        require(!proof.rollbackToAbsentPerformed)
        require(!proof.arbitraryCommandAccepted && !proof.privateKeyContentReadPerformed)
        require(!proof.webServerReloadPerformed)
        require(!proof.dnsMutationPerformed && !proof.firewallMutationPerformed && !proof.packageInstallPerformed)
        require(!proof.automaticRetryPerformed && !proof.coordinatorInvoked && !proof.exposesDeployUiAction)
        require(proof.executedAtEpochMillis >= proof.credentialResolvedAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.freshCredentialAuthorizationExpiresAtEpochMillis)
        listOf(
            proof.activationPlanSha256,
            proof.stagingSyntaxExecutionPlanSha256,
            proof.stagingSyntaxExecutionProofSha256,
            proof.mutationPreparationSha256,
            proof.publicationPlanSha256,
            proof.readOnlyPreflightSha256,
            proof.freshCredentialResolutionProofSha256,
            proof.freshCredentialResolutionConsumptionReceiptSha256,
            proof.serverAccessBindingSha256,
            proof.pinnedHostKeySha256,
            proof.secretReferenceSha256,
            proof.executionProofSha256,
        ).forEach { require(sha256.matches(it)) }
        require(proof.executionProofSha256 == proofSha256(proof.copy(executionProofSha256 = "")))
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
            SecretCreateResult.StorageFailure("Phase 11.60 lease adapter is read-only")
        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.60 lease adapter is read-only")
        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.60 lease adapter does not enumerate secrets")
    }

    private fun secretReferenceSha256(serverAccessId: String, type: String, secretId: String): String = digest(buildString {
        append("serverAccessId=").append(serverAccessId).append('\n')
        append("secretReferenceType=").append(type).append('\n')
        append("secretId=").append(secretId).append('\n')
    })

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        type: String,
        secretSha: String,
        pinSha: String,
    ): String = digest(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("serverId=").append(serverAccess.serverId.value).append('\n')
        append("host=").append(serverAccess.endpoint.host).append('\n')
        append("port=").append(serverAccess.endpoint.port).append('\n')
        append("username=").append(serverAccess.username).append('\n')
        append("secretReferenceType=").append(type).append('\n')
        append("secretReferenceSha256=").append(secretSha).append('\n')
        append("pinnedHostKeySha256=").append(pinSha).append('\n')
    })

    private fun proofSha256(proof: SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionProof): String = digest(buildString {
        append("phase=11.60\n")
        append("contractVersion=").append(proof.contractVersion).append('\n')
        append("status=").append(proof.status.name).append('\n')
        append("activationPlan=").append(proof.activationPlanSha256).append('\n')
        append("stagingSyntaxPlan=").append(proof.stagingSyntaxExecutionPlanSha256).append('\n')
        append("stagingSyntaxProof=").append(proof.stagingSyntaxExecutionProofSha256).append('\n')
        append("mutationPreparation=").append(proof.mutationPreparationSha256).append('\n')
        append("publicationPlan=").append(proof.publicationPlanSha256).append('\n')
        append("preflight=").append(proof.readOnlyPreflightSha256).append('\n')
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
        append("successfulStagingSyntaxProofValidated=").append(proof.successfulStagingSyntaxProofValidated).append('\n')
        append("durablePreactivationCheckpointRecorded=").append(proof.durablePreactivationCheckpointRecorded).append('\n')
        append("credentialLeaseMaterialConsumed=").append(proof.credentialLeaseMaterialConsumed).append('\n')
        append("productionNetworkTouched=").append(proof.productionNetworkTouched).append('\n')
        append("hostKeyPinVerifiedAgainstRemote=").append(proof.hostKeyPinVerifiedAgainstRemote).append('\n')
        append("exactSessionRegistryUsed=").append(proof.exactSessionRegistryUsed).append('\n')
        append("mutationOperationPerformed=").append(proof.mutationOperationPerformed).append('\n')
        append("stagingConfigWritePerformed=").append(proof.stagingConfigWritePerformed).append('\n')
        append("stagingConfigSha256Verified=").append(proof.stagingConfigSha256Verified).append('\n')
        append("exactConfigActivationPerformed=").append(proof.exactConfigActivationPerformed).append('\n')
        append("exactConfigSha256Verified=").append(proof.exactConfigSha256Verified).append('\n')
        append("nginxSyntaxValidationPassed=").append(proof.nginxSyntaxValidationPassed).append('\n')
        append("exactConfigPathPresentAfterActivation=").append(proof.exactConfigPathPresentAfterActivation).append('\n')
        append("stagingConfigAbsentAfterActivation=").append(proof.stagingConfigAbsentAfterActivation).append('\n')
        append("listenerStillFreeAfterActivation=").append(proof.listenerStillFreeAfterActivation).append('\n')
        append("rollbackToAbsentPerformed=").append(proof.rollbackToAbsentPerformed).append('\n')
        append("arbitraryCommandAccepted=").append(proof.arbitraryCommandAccepted).append('\n')
        append("privateKeyContentReadPerformed=").append(proof.privateKeyContentReadPerformed).append('\n')
        append("webServerReloadPerformed=").append(proof.webServerReloadPerformed).append('\n')
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
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.trim().lowercase()
        return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
    }
}

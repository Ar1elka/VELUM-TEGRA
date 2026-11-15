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
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteWebServingLiveHttpVerificationSshAdapter
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/** Phase 11.62 performs one bounded read-only loopback HTTP verification after Phase 11.61. */
internal object SiteProductionDeploymentAndroidRealVpsWebServingLiveHttpVerificationExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun executeOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        reloadProof: SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionProof,
        verificationPlan: SiteWebServingLiveHttpVerificationPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionProof {
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingNginxReloadExecutionBoundary.validate(reloadPlan)
        SiteWebServingLiveHttpVerificationBoundary.validate(verificationPlan)
        SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary.validateProof(reloadProof)
        require(verificationPlan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(verificationPlan.reloadPlanSha256 == reloadPlan.reloadPlanSha256)
        require(reloadProof.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(reloadProof.reloadPlanSha256 == reloadPlan.reloadPlanSha256)
        require(reloadProof.nginxReloadPerformed)
        require(reloadProof.exactConfigSha256VerifiedAfterReload)
        require(reloadProof.nginxMasterRunningAfterReload)
        require(reloadProof.expectedListenerLiveAfterReload)
        require(!reloadProof.configMutationPerformed)
        require(!reloadProof.dnsMutationPerformed && !reloadProof.firewallMutationPerformed)
        require(!reloadProof.packageInstallPerformed && !reloadProof.automaticRetryPerformed)

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
            is HostKeyFingerprintParseResult.Invalid -> throw IllegalArgumentException("Phase 11.62 pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        val bindingSha256 = serverAccessBindingSha256(serverAccess, secretReferenceType, secretReferenceSha256, expectedHostKeySha256)
        require(freshResolutionProof.serverAccessBindingSha256 == bindingSha256)

        val ownerId = "phase11_62_${verificationPlan.verificationPlanSha256.take(24)}"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId("phase11_62_session_${verificationPlan.verificationPlanSha256.take(24)}")
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
                    stdoutCaptureLimitBytes = verificationPlan.expectedBodyBytes + verificationPlan.maxHeaderBytes + 4096,
                    stderrCaptureLimitBytes = 32 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Phase 11.62 fresh SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close(); throw IllegalArgumentException("Phase 11.62 missing verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256)
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)

            val observation = SiteWebServingLiveHttpVerificationSshAdapter().verifyOnce(
                verificationPlan = verificationPlan,
                publicationPlan = publicationPlan,
                access = serverAccess,
                session = verified,
            )
            require(observation.verifiedHostKeySha256 == expectedHostKeySha256)
            val sessionIdValue = verified.binding.sessionId.value
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0 && !verified.isOpen)
            connectedHandle = null

            val base = SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionStatus.LIVE_HTTP_INDEX_VERIFIED_OVER_REMOTE_LOOPBACK,
                verificationPlanSha256 = verificationPlan.verificationPlanSha256,
                preparationSha256 = verificationPlan.preparationSha256,
                publicationPlanSha256 = publicationPlan.publicationPlanSha256,
                reloadPlanSha256 = reloadPlan.reloadPlanSha256,
                reloadExecutionProofSha256 = reloadProof.executionProofSha256,
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
                executionAttemptId = executionAttemptId,
                remoteCommandCount = observation.remoteCommandCount,
                successfulReloadProofValidated = true,
                exactConfigSha256Verified = observation.exactConfigSha256Verified,
                nginxMasterRunning = observation.nginxMasterRunning,
                expectedListenerLive = observation.expectedListenerLive,
                loopbackHttpGetPerformed = observation.loopbackHttpGetPerformed,
                httpStatusCode = observation.httpStatusCode,
                contentLength = observation.contentLength,
                expectedBodySha256 = verificationPlan.expectedBodySha256,
                observedBodySha256 = observation.observedBodySha256,
                exactBodySha256Verified = observation.exactBodySha256Verified,
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
                externalReachabilityClaimed = false,
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

    fun validateProof(proof: SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(proof.status == SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionStatus.LIVE_HTTP_INDEX_VERIFIED_OVER_REMOTE_LOOPBACK)
        require(proof.successfulReloadProofValidated)
        require(proof.exactConfigSha256Verified && proof.nginxMasterRunning && proof.expectedListenerLive)
        require(proof.loopbackHttpGetPerformed)
        require(proof.httpStatusCode == 200)
        require(proof.contentLength > 0)
        require(proof.expectedBodySha256 == proof.observedBodySha256)
        require(proof.exactBodySha256Verified)
        require(proof.remoteCommandCount == 1)
        require(proof.credentialLeaseMaterialConsumed && proof.productionNetworkTouched)
        require(proof.hostKeyPinVerifiedAgainstRemote && proof.exactSessionRegistryUsed && proof.sessionClosed)
        require(!proof.arbitraryCommandAccepted && !proof.configMutationPerformed && !proof.privateKeyContentReadPerformed)
        require(!proof.dnsMutationPerformed && !proof.firewallMutationPerformed && !proof.packageInstallPerformed)
        require(!proof.automaticRetryPerformed && !proof.externalReachabilityClaimed)
        require(!proof.coordinatorInvoked && !proof.exposesDeployUiAction)
        require(canonicalId.matches(proof.executionAttemptId))
        require(proof.executedAtEpochMillis >= proof.credentialResolvedAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.freshCredentialAuthorizationExpiresAtEpochMillis)
        listOf(
            proof.verificationPlanSha256,
            proof.preparationSha256,
            proof.publicationPlanSha256,
            proof.reloadPlanSha256,
            proof.reloadExecutionProofSha256,
            proof.freshCredentialResolutionProofSha256,
            proof.freshCredentialResolutionConsumptionReceiptSha256,
            proof.serverAccessBindingSha256,
            proof.pinnedHostKeySha256,
            proof.secretReferenceSha256,
            proof.expectedBodySha256,
            proof.observedBodySha256,
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
            if (!readStarted.compareAndSet(false, true)) return SecretReadResult.Unavailable("Ephemeral credential lease is single-use")
            val copy = credentialLease.useMaterialOnce { material -> material.useBytes { SecretMaterial.fromBytes(it) } }
            return SecretReadResult.Found(copy)
        }
        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult = SecretCreateResult.StorageFailure("Phase 11.62 lease adapter is read-only")
        override suspend fun delete(secretId: SecretId): SecretDeleteResult = SecretDeleteResult.StorageFailure("Phase 11.62 lease adapter is read-only")
        override suspend fun listIds(): SecretListResult = SecretListResult.StorageFailure("Phase 11.62 lease adapter does not enumerate secrets")
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

    private fun proofSha256(proof: SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionProof): String = digest(buildString {
        append("phase=11.62\n")
        append("contractVersion=").append(proof.contractVersion).append('\n')
        append("status=").append(proof.status.name).append('\n')
        append("verificationPlan=").append(proof.verificationPlanSha256).append('\n')
        append("preparation=").append(proof.preparationSha256).append('\n')
        append("publicationPlan=").append(proof.publicationPlanSha256).append('\n')
        append("reloadPlan=").append(proof.reloadPlanSha256).append('\n')
        append("reloadProof=").append(proof.reloadExecutionProofSha256).append('\n')
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
        append("executionAttemptId=").append(proof.executionAttemptId).append('\n')
        append("remoteCommandCount=").append(proof.remoteCommandCount).append('\n')
        append("successfulReloadProofValidated=").append(proof.successfulReloadProofValidated).append('\n')
        append("exactConfigSha256Verified=").append(proof.exactConfigSha256Verified).append('\n')
        append("nginxMasterRunning=").append(proof.nginxMasterRunning).append('\n')
        append("expectedListenerLive=").append(proof.expectedListenerLive).append('\n')
        append("loopbackHttpGetPerformed=").append(proof.loopbackHttpGetPerformed).append('\n')
        append("httpStatusCode=").append(proof.httpStatusCode).append('\n')
        append("contentLength=").append(proof.contentLength).append('\n')
        append("expectedBodySha256=").append(proof.expectedBodySha256).append('\n')
        append("observedBodySha256=").append(proof.observedBodySha256).append('\n')
        append("exactBodySha256Verified=").append(proof.exactBodySha256Verified).append('\n')
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
        append("externalReachabilityClaimed=").append(proof.externalReachabilityClaimed).append('\n')
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

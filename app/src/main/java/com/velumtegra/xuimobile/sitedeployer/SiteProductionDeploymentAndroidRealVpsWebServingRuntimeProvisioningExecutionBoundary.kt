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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionUsePort
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimePrerequisiteBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimePrerequisiteReport
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimeProvisioningBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimeProvisioningPlan
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteWebServingRuntimeProvisioningSshAdapter
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Phase 11.59B performs one exact nginx apt provisioning attempt on one fresh pinned SSH session.
 * The durable replay fence is consumed after a read-only baseline guard and before apt metadata or
 * package mutation. Dispatch uncertainty/failure is never retried automatically.
 */
internal object SiteProductionDeploymentAndroidRealVpsWebServingRuntimeProvisioningExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun executeOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        prerequisiteReport: SiteWebServingRuntimePrerequisiteReport,
        provisioningPlan: SiteWebServingRuntimeProvisioningPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionUsePort,
    ): SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionProof {
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        SiteWebServingRuntimePrerequisiteBoundary.validateReport(prerequisiteReport)
        SiteWebServingRuntimeProvisioningBoundary.validateAgainst(
            provisioningPlan,
            publicationPlan,
            prerequisiteReport,
        )
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(freshResolutionProof)
        require(publicationPlan.remoteHostIdentity == serverAccess.endpoint.host)
        require(!isLoopbackHost(serverAccess.endpoint.host))
        require(serverAccess.endpoint.port in 1..65535)
        require(serverAccess.username == "root")
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
        require(
            freshCredentialLease.authorizationExpiresAtEpochMillis ==
                freshResolutionProof.authorizationExpiresAtEpochMillis,
        )

        val expectedHostKey = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid ->
                throw IllegalArgumentException("Phase 11.59B pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        val bindingSha256 = serverAccessBindingSha256(
            serverAccess,
            secretReferenceType,
            secretReferenceSha256,
            expectedHostKeySha256,
        )
        require(freshResolutionProof.serverAccessBindingSha256 == bindingSha256)

        val ownerId = "phase11_59b_${provisioningPlan.provisioningPlanSha256.take(22)}"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId("phase11_59b_session_${provisioningPlan.provisioningPlanSha256.take(22)}")
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
                    commandExecutionTimeout = Duration.ofMinutes(4),
                    stdoutCaptureLimitBytes = 256 * 1024,
                    stderrCaptureLimitBytes = 256 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Phase 11.59B fresh SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException("Phase 11.59B missing verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256)
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)

            val adapter = SiteWebServingRuntimeProvisioningSshAdapter()
            val liveHostKeySha = adapter.verifyBeforeMutation(
                plan = provisioningPlan,
                access = serverAccess,
                session = verified,
            )
            require(liveHostKeySha == expectedHostKeySha256)
            require(executionUsePort.consumeOnce(provisioningPlan.provisioningPlanSha256)) {
                "Phase 11.59B durable predispatch checkpoint/replay fence rejected provisioning plan"
            }
            val observation = adapter.provisionAndVerify(
                plan = provisioningPlan,
                access = serverAccess,
                session = verified,
                verifiedHostKeySha256 = liveHostKeySha,
            )

            val sessionIdValue = verified.binding.sessionId.value
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0 && !verified.isOpen)
            connectedHandle = null

            val base = SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionStatus
                    .NGINX_APT_PROVISIONED_AND_VERIFIED_REQUIRES_FRESH_WEB_SERVING_PREFLIGHT,
                provisioningPlanSha256 = provisioningPlan.provisioningPlanSha256,
                prerequisiteReportSha256 = prerequisiteReport.reportSha256,
                publicationPlanSha256 = publicationPlan.publicationPlanSha256,
                observation = observation,
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
                durablePredispatchCheckpointRecorded = observation.durablePredispatchCheckpointRecorded,
                credentialLeaseMaterialConsumed = true,
                productionNetworkTouched = true,
                hostKeyPinVerifiedAgainstRemote = true,
                exactSessionRegistryUsed = true,
                mutationOperationPerformed = true,
                aptMetadataRefreshPerformed = observation.aptMetadataRefreshPerformed,
                packageInstallPerformed = observation.packageInstallPerformed,
                packageManagedConfigFilesObserved = observation.packageManagedConfigFilesObserved,
                packageManagedServiceLifecycleMayHaveOccurred = observation.packageManagedServiceLifecycleMayHaveOccurred,
                siteConfigMutationPerformed = observation.siteConfigMutationPerformed,
                explicitServiceCommandPerformed = observation.explicitServiceCommandPerformed,
                webServerReloadPerformed = observation.webServerReloadPerformed,
                dnsMutationPerformed = observation.dnsMutationPerformed,
                firewallMutationPerformed = observation.firewallMutationPerformed,
                arbitraryCommandAccepted = observation.arbitraryCommandAccepted,
                privateKeyContentReadPerformed = false,
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

    fun validateProof(proof: SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(
            proof.status == SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionStatus
                .NGINX_APT_PROVISIONED_AND_VERIFIED_REQUIRES_FRESH_WEB_SERVING_PREFLIGHT,
        )
        val observation = proof.observation
        require(proof.durablePredispatchCheckpointRecorded && observation.durablePredispatchCheckpointRecorded)
        require(proof.credentialLeaseMaterialConsumed)
        require(proof.productionNetworkTouched && proof.hostKeyPinVerifiedAgainstRemote)
        require(proof.exactSessionRegistryUsed && proof.sessionClosed)
        require(proof.remoteCommandCount == 4 && observation.remoteCommandCount == 4)
        require(proof.mutationOperationPerformed)
        require(proof.aptMetadataRefreshPerformed && proof.packageInstallPerformed)
        require(observation.cleanMissingNginxBaselineRevalidated)
        require(observation.packageInstalledByDpkg)
        require(observation.nginxExecutablePath.startsWith('/'))
        require(observation.nginxRootDirectoryPresent && observation.confDDirectoryPresent)
        require(observation.nginxSyntaxValidationPassed)
        require(observation.exactConfigPathAbsentAfterProvisioning)
        require(observation.listenerStillFreeAfterProvisioning)
        require(proof.packageManagedConfigFilesObserved)
        require(proof.packageManagedServiceLifecycleMayHaveOccurred)
        require(!proof.siteConfigMutationPerformed)
        require(!proof.explicitServiceCommandPerformed && !proof.webServerReloadPerformed)
        require(!proof.dnsMutationPerformed && !proof.firewallMutationPerformed)
        require(!proof.arbitraryCommandAccepted && !proof.privateKeyContentReadPerformed)
        require(!proof.automaticRetryPerformed && !proof.coordinatorInvoked && !proof.exposesDeployUiAction)
        require(proof.executedAtEpochMillis >= proof.credentialResolvedAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.freshCredentialAuthorizationExpiresAtEpochMillis)
        listOf(
            proof.provisioningPlanSha256,
            proof.prerequisiteReportSha256,
            proof.publicationPlanSha256,
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
            SecretCreateResult.StorageFailure("Phase 11.59B lease adapter is read-only")

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.59B lease adapter is read-only")

        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.59B lease adapter does not enumerate secrets")
    }

    private fun secretReferenceSha256(serverAccessId: String, type: String, secretId: String): String =
        digest(buildString {
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

    private fun proofSha256(
        proof: SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionProof,
    ): String = digest(buildString {
        append("phase=11.59B\n")
        append("contractVersion=").append(proof.contractVersion).append('\n')
        append("status=").append(proof.status.name).append('\n')
        append("provisioningPlan=").append(proof.provisioningPlanSha256).append('\n')
        append("prerequisiteReport=").append(proof.prerequisiteReportSha256).append('\n')
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
        append("durablePredispatchCheckpointRecorded=").append(proof.durablePredispatchCheckpointRecorded).append('\n')
        append("credentialLeaseMaterialConsumed=").append(proof.credentialLeaseMaterialConsumed).append('\n')
        append("productionNetworkTouched=").append(proof.productionNetworkTouched).append('\n')
        append("hostKeyPinVerifiedAgainstRemote=").append(proof.hostKeyPinVerifiedAgainstRemote).append('\n')
        append("exactSessionRegistryUsed=").append(proof.exactSessionRegistryUsed).append('\n')
        append("mutationOperationPerformed=").append(proof.mutationOperationPerformed).append('\n')
        append("aptMetadataRefreshPerformed=").append(proof.aptMetadataRefreshPerformed).append('\n')
        append("packageInstallPerformed=").append(proof.packageInstallPerformed).append('\n')
        append("packageManagedConfigFilesObserved=").append(proof.packageManagedConfigFilesObserved).append('\n')
        append("packageManagedServiceLifecycleMayHaveOccurred=").append(proof.packageManagedServiceLifecycleMayHaveOccurred).append('\n')
        append("siteConfigMutationPerformed=").append(proof.siteConfigMutationPerformed).append('\n')
        append("explicitServiceCommandPerformed=").append(proof.explicitServiceCommandPerformed).append('\n')
        append("webServerReloadPerformed=").append(proof.webServerReloadPerformed).append('\n')
        append("dnsMutationPerformed=").append(proof.dnsMutationPerformed).append('\n')
        append("firewallMutationPerformed=").append(proof.firewallMutationPerformed).append('\n')
        append("arbitraryCommandAccepted=").append(proof.arbitraryCommandAccepted).append('\n')
        append("privateKeyContentReadPerformed=").append(proof.privateKeyContentReadPerformed).append('\n')
        append("automaticRetryPerformed=").append(proof.automaticRetryPerformed).append('\n')
        append("sessionClosed=").append(proof.sessionClosed).append('\n')
        append("coordinatorInvoked=").append(proof.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(proof.exposesDeployUiAction).append('\n')
        append("credentialResolvedAt=").append(proof.credentialResolvedAtEpochMillis).append('\n')
        append("executedAt=").append(proof.executedAtEpochMillis).append('\n')
        append("authorizationExpiresAt=").append(proof.freshCredentialAuthorizationExpiresAtEpochMillis).append('\n')
        val o = proof.observation
        append("obsHost=").append(o.remoteHostIdentity).append('\n')
        append("obsPin=").append(o.verifiedHostKeySha256).append('\n')
        append("obsNginx=").append(o.nginxExecutablePath).append('\n')
        append("obsDpkg=").append(o.packageInstalledByDpkg).append('\n')
        append("obsRoot=").append(o.nginxRootDirectoryPresent).append('\n')
        append("obsConfD=").append(o.confDDirectoryPresent).append('\n')
        append("obsSyntax=").append(o.nginxSyntaxValidationPassed).append('\n')
        append("obsConfigAbsent=").append(o.exactConfigPathAbsentAfterProvisioning).append('\n')
        append("obsPortFree=").append(o.listenerStillFreeAfterProvisioning).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.trim().lowercase()
        return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
    }
}

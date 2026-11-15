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
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionUsePort
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightEvidence
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Phase 11.50 performs exactly one real-VPS bounded SFTP read-only preflight after the exact
 * Phase 11.49 durable handoff consumption.
 *
 * Counteraction precedes action: the exact Phase 11.49 receipt is durably burned in a dedicated
 * execution namespace before fresh credential material can be consumed or production network can
 * be touched. The execution then requires a fresh post-11.49 credential-resolution proof and lease,
 * acquires one fresh pinned SSH session, opens one fresh SFTP channel and delegates only to the
 * reviewed SiteRemoteSftpReadOnlyPreflightProbe. The allowed remote vocabulary remains exactly
 * three lstat observations plus one bounded list of the exact target root. No file-content read,
 * command, write, rename, mkdir, chmod/chown, delete, coordinator call or deploy UI is available.
 */
internal object SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun observeRealVpsReadOnlyPreflightOnce(
        receipt: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionReceipt,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionUsePort,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionProof {
        SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightHandoffConsumptionBoundary
            .validateReceipt(receipt)
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
            .validateProof(freshResolutionProof)

        require(receipt.singleUseConsumed)
        require(receipt.requiresFreshCredentialResolutionBeforeReadOnlyExecution)
        require(receipt.requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution)
        require(receipt.requiresFreshLiveRemoteHostKeyVerificationBeforeReadOnlyExecution)
        require(receipt.requiresFreshSftpChannelOpenBeforeReadOnlyExecution)
        require(receipt.requiresSeparateReadOnlyExecutionBoundary)
        require(!receipt.authorizesMutation)
        require(!receipt.authorizesCoordinatorInvocation)
        require(!receipt.exposesDeployUiAction)
        require(receipt.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        require(receipt.maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(
            receipt.approvedReadOnlyOperationVocabulary ==
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
        )

        require(
            freshResolutionProof.status ==
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.RESOLVED_TO_EPHEMERAL_LEASE,
        ) { "Phase 11.50 requires a successful fresh credential-resolution proof" }
        require(freshResolutionProof.secretStoreReadPerformed)
        require(!freshResolutionProof.credentialLeaseMaterialRead)
        require(!freshResolutionProof.productionNetworkTouched)
        require(freshResolutionProof.requiresLiveRemoteHostKeyVerification)
        require(freshResolutionProof.requiresSeparateSshSessionAcquisitionBoundary)
        require(freshResolutionProof.requiresSeparateSftpChannelOpenBoundary)
        require(freshResolutionProof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(freshResolutionProof.resolvedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "Real-VPS read-only preflight requires credential resolution after Phase 11.49 consumption"
        }
        require(freshResolutionProof.resolvedAtEpochMillis <= executedAtEpochMillis)
        require(executedAtEpochMillis >= receipt.consumedAtEpochMillis)
        require(executedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "Real-VPS read-only preflight authorization expired before execution"
        }
        require(executedAtEpochMillis <= freshResolutionProof.authorizationExpiresAtEpochMillis) {
            "Fresh credential-resolution authorization expired before read-only preflight"
        }
        require(canonicalId.matches(executionAttemptId)) {
            "Real-VPS read-only preflight execution attempt id must be canonical"
        }

        require(serverAccess.id.value == receipt.serverAccessId)
        require(serverAccess.endpoint.host == receipt.remoteHostIdentity)
        require(serverAccess.endpoint.port == receipt.remotePort && receipt.remotePort in 1..65535)
        require(serverAccess.username == receipt.username)
        require(!isLoopbackHost(serverAccess.endpoint.host)) {
            "Phase 11.50 requires the exact reviewed non-loopback real-VPS endpoint"
        }

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
            "Real-VPS read-only preflight SecretId binding mismatch"
        }

        val expectedHostKey = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid ->
                throw IllegalArgumentException("Real-VPS read-only preflight pinned host key is invalid")
        }
        val expectedHostKeySha256 = expectedHostKey.asHexSha256()
        require(expectedHostKeySha256 == receipt.pinnedHostKeySha256)
        require(
            serverAccessBindingSha256(
                serverAccess = serverAccess,
                secretReferenceType = secretReferenceType,
                secretReferenceSha256 = secretReferenceSha256,
                pinnedHostKeySha256 = expectedHostKeySha256,
            ) == receipt.serverAccessBindingSha256,
        ) { "Real-VPS read-only preflight ServerAccess binding drifted" }

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
        )
        require(freshCredentialLease.resolvedAtEpochMillis == freshResolutionProof.resolvedAtEpochMillis)
        require(
            freshCredentialLease.authorizationExpiresAtEpochMillis ==
                freshResolutionProof.authorizationExpiresAtEpochMillis,
        )

        // Durable burn before any fresh lease material read or production network activity.
        require(executionUsePort.consumeOnce(receipt.readOnlyPreflightConsumptionReceiptSha256)) {
            "Real-VPS read-only preflight execution receipt was already used or replay fence failed closed"
        }

        val ownerId = "phase11_50_$executionAttemptId"
        val owner = SessionOwner.Operation(OperationId(ownerId))
        val deterministicSessionId = SessionId(
            "phase11_50_session_${receipt.readOnlyPreflightConsumptionReceiptSha256.take(24)}",
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
                    "Real-VPS read-only preflight fresh SSH acquisition failed closed: " +
                        ((connectResult as SshConnectResult.Failed).failure::class.java.simpleName),
                )
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException(
                    "Real-VPS read-only preflight did not receive verified host-key evidence",
                )
            }
            connectedHandle = verified
            require(verified.isOpen)
            require(verified.binding.serverAccessId == serverAccess.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == deterministicSessionId)
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256) {
                "Real-VPS read-only preflight fresh live host-key verification did not match the reviewed pin"
            }
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, serverAccess.id) === verified)

            val evidence = SiteRemoteSftpReadOnlyPreflightProbe().observe(
                session = verified,
                targetRoot = receipt.targetRoot,
                stagingRoot = receipt.stagingRoot,
                backupRoot = receipt.backupRoot,
                expectedTargetEntryNames = receipt.expectedTargetEntryNames,
                channelOpenTimeout = Duration.ofSeconds(5),
            )
            require(evidence.channelOpened && evidence.channelClosed)
            require(evidence.lstatOperationCount == 3)
            require(evidence.listOperationCount == 1)
            require(!evidence.mutationOperationPerformed)
            require(!evidence.remoteCommandDispatched)
            require(evidence.target.path == receipt.targetRoot)
            require(evidence.staging.path == receipt.stagingRoot)
            require(evidence.backup.path == receipt.backupRoot)
            require(evidence.targetEntryNames == receipt.expectedTargetEntryNames)

            val observationSha256 = observationSha256(evidence)
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

            val base = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionProof(
                contractVersion = CONTRACT_VERSION,
                status = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionStatus
                    .REAL_VPS_BOUNDED_SFTP_READ_ONLY_PREFLIGHT_VERIFIED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
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
                boundedReadOnlyPreflightPerformed = true,
                remoteMetadataReadPerformed = true,
                fileContentReadPerformed = false,
                lstatOperationCount = evidence.lstatOperationCount,
                listOperationCount = evidence.listOperationCount,
                mutationOperationPerformed = false,
                remoteCommandDispatched = false,
                sessionClosed = true,
                coordinatorInvoked = false,
                exposesDeployUiAction = false,
                realVpsAccessPerformed = true,
                requiresSeparateMutationBoundary = true,
                authorizationSha256 = receipt.authorizationSha256,
                readOnlyPreflightConsumptionReceiptSha256 = receipt.readOnlyPreflightConsumptionReceiptSha256,
                priorSftpExecutionProofSha256 = receipt.priorSftpExecutionProofSha256,
                priorSftpExecutionReceiptSha256 = receipt.priorSftpExecutionReceiptSha256,
                preflightHandoffConsumptionReceiptSha256 = receipt.preflightHandoffConsumptionReceiptSha256,
                sourcePreflightAuthorizationSha256 = receipt.sourcePreflightAuthorizationSha256,
                admissionSha256 = receipt.admissionSha256,
                freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
                freshCredentialResolutionConsumptionReceiptSha256 =
                    freshResolutionProof.credentialResolutionConsumptionReceiptSha256,
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
                approvedReadOnlyOperationVocabulary = receipt.approvedReadOnlyOperationVocabulary,
                maxTargetEntries = receipt.maxTargetEntries,
                sftpReadOnlyProbeImplementation = SiteRemoteSftpReadOnlyPreflightProbe::class.java.name,
                targetRoot = evidence.target.path,
                targetType = evidence.target.type,
                stagingRoot = evidence.staging.path,
                stagingType = evidence.staging.type,
                backupRoot = evidence.backup.path,
                backupType = evidence.backup.type,
                targetEntryNames = evidence.targetEntryNames,
                observationSha256 = observationSha256,
                credentialStoreImplementation = freshResolutionProof.credentialStoreImplementation,
                sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
                exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
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

    fun validateProof(proof: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(
            proof.status == SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionStatus
                .REAL_VPS_BOUNDED_SFTP_READ_ONLY_PREFLIGHT_VERIFIED_WITH_FRESH_CREDENTIAL_AND_LIVE_HOST_KEY,
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
        require(proof.boundedReadOnlyPreflightPerformed)
        require(proof.remoteMetadataReadPerformed)
        require(!proof.fileContentReadPerformed)
        require(proof.lstatOperationCount == 3)
        require(proof.listOperationCount == 1)
        require(!proof.mutationOperationPerformed)
        require(!proof.remoteCommandDispatched)
        require(proof.sessionClosed)
        require(!proof.coordinatorInvoked)
        require(!proof.exposesDeployUiAction)
        require(proof.realVpsAccessPerformed)
        require(proof.requiresSeparateMutationBoundary)
        require(!isLoopbackHost(proof.remoteHostIdentity))
        require(proof.remotePort in 1..65535)
        require(proof.username.isNotBlank())
        require(proof.targetType == SiteRemoteObservedPathType.DIRECTORY)
        require(proof.stagingType == SiteRemoteObservedPathType.ABSENT)
        require(proof.backupType == SiteRemoteObservedPathType.ABSENT)
        require(proof.targetEntryNames.isNotEmpty())
        require(proof.targetEntryNames == proof.targetEntryNames.sorted())
        require(proof.targetEntryNames.size <= proof.maxTargetEntries)
        require(proof.maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(
            proof.approvedReadOnlyOperationVocabulary ==
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
        )
        require(proof.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        require(proof.credentialResolvedAtEpochMillis >= proof.handoffConsumedAtEpochMillis)
        require(proof.executedAtEpochMillis >= proof.credentialResolvedAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.authorizationExpiresAtEpochMillis)
        require(proof.executedAtEpochMillis <= proof.freshCredentialAuthorizationExpiresAtEpochMillis)
        require(proof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(proof.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(proof.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(proof.verifiedHostKeySha256 == proof.pinnedHostKeySha256)
        validateHashes(
            proof.authorizationSha256,
            proof.readOnlyPreflightConsumptionReceiptSha256,
            proof.priorSftpExecutionProofSha256,
            proof.priorSftpExecutionReceiptSha256,
            proof.preflightHandoffConsumptionReceiptSha256,
            proof.sourcePreflightAuthorizationSha256,
            proof.admissionSha256,
            proof.freshCredentialResolutionProofSha256,
            proof.freshCredentialResolutionConsumptionReceiptSha256,
            proof.serverAccessBindingSha256,
            proof.requestSha256,
            proof.capabilityProfileSha256,
            proof.pinnedHostKeySha256,
            proof.secretReferenceSha256,
            proof.observationSha256,
            proof.verifiedHostKeySha256,
            proof.executionProofSha256,
        )
        require(proof.executionProofSha256 == proofSha256(proof.copy(executionProofSha256 = ""))) {
            "Real-VPS read-only preflight execution proof SHA-256 mismatch"
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
            SecretCreateResult.StorageFailure("Phase 11.50 lease adapter is read-only")

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.50 lease adapter is read-only")

        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.50 lease adapter does not enumerate secrets")
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

    private fun observationSha256(evidence: SiteRemoteSftpReadOnlyPreflightEvidence): String = sha256(buildString {
        listOf(evidence.target, evidence.staging, evidence.backup).forEach { path ->
            append("path=").append(path.path)
                .append('|').append(path.type.name)
                .append('|').append(path.sizeBytes)
                .append('|').append(path.uid)
                .append('|').append(path.gid)
                .append('|').append(path.permissions)
                .append('\n')
        }
        evidence.targetEntryNames.forEach { append("entry=").append(it).append('\n') }
        append("lstat=").append(evidence.lstatOperationCount).append('\n')
        append("list=").append(evidence.listOperationCount).append('\n')
    })

    private fun proofSha256(proof: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionProof): String =
        sha256(buildString {
            append("phase=11.50\n")
            append("contractVersion=").append(proof.contractVersion).append('\n')
            append("status=").append(proof.status.name).append('\n')
            append("authorization=").append(proof.authorizationSha256).append('\n')
            append("consumption=").append(proof.readOnlyPreflightConsumptionReceiptSha256).append('\n')
            append("priorSftpProof=").append(proof.priorSftpExecutionProofSha256).append('\n')
            append("priorSftpReceipt=").append(proof.priorSftpExecutionReceiptSha256).append('\n')
            append("preflightHandoff=").append(proof.preflightHandoffConsumptionReceiptSha256).append('\n')
            append("sourcePreflightAuthorization=").append(proof.sourcePreflightAuthorizationSha256).append('\n')
            append("admission=").append(proof.admissionSha256).append('\n')
            append("freshResolutionProof=").append(proof.freshCredentialResolutionProofSha256).append('\n')
            append("freshResolutionReceipt=").append(proof.freshCredentialResolutionConsumptionReceiptSha256).append('\n')
            append("binding=").append(proof.serverAccessBindingSha256).append('\n')
            append("request=").append(proof.requestSha256).append('\n')
            append("capability=").append(proof.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(proof.serverAccessId).append('\n')
            append("host=").append(proof.remoteHostIdentity).append('\n')
            append("port=").append(proof.remotePort).append('\n')
            append("username=").append(proof.username).append('\n')
            append("pinnedHostKey=").append(proof.pinnedHostKeySha256).append('\n')
            append("secretReferenceType=").append(proof.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(proof.secretReferenceSha256).append('\n')
            proof.approvedReadOnlyOperationVocabulary.forEach { append("operation=").append(it).append('\n') }
            append("maxTargetEntries=").append(proof.maxTargetEntries).append('\n')
            append("probe=").append(proof.sftpReadOnlyProbeImplementation).append('\n')
            append("target=").append(proof.targetRoot).append('|').append(proof.targetType.name).append('\n')
            append("staging=").append(proof.stagingRoot).append('|').append(proof.stagingType.name).append('\n')
            append("backup=").append(proof.backupRoot).append('|').append(proof.backupType.name).append('\n')
            proof.targetEntryNames.forEach { append("entry=").append(it).append('\n') }
            append("observation=").append(proof.observationSha256).append('\n')
            append("credentialStore=").append(proof.credentialStoreImplementation).append('\n')
            append("sshFactory=").append(proof.sshConnectionFactoryImplementation).append('\n')
            append("registry=").append(proof.exactSessionRegistryImplementation).append('\n')
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
            append("boundedReadOnlyPreflightPerformed=").append(proof.boundedReadOnlyPreflightPerformed).append('\n')
            append("remoteMetadataReadPerformed=").append(proof.remoteMetadataReadPerformed).append('\n')
            append("fileContentReadPerformed=").append(proof.fileContentReadPerformed).append('\n')
            append("lstat=").append(proof.lstatOperationCount).append('\n')
            append("list=").append(proof.listOperationCount).append('\n')
            append("mutation=").append(proof.mutationOperationPerformed).append('\n')
            append("command=").append(proof.remoteCommandDispatched).append('\n')
        })

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS read-only preflight execution hashes must be lowercase SHA-256"
        }
    }

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.lowercase()
        return normalized == "localhost" ||
            normalized == "::1" ||
            normalized == "[::1]" ||
            normalized.startsWith("127.")
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

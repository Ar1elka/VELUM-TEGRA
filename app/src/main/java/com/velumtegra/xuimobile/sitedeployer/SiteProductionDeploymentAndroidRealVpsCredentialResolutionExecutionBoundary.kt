package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsCredentialResolutionExecutionUsePort
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import java.security.MessageDigest

/**
 * Phase 11.41 one-shot real-VPS credential-resolution execution boundary.
 *
 * It accepts only the exact Phase 11.40 durable receipt, revalidates the exact public ServerAccess
 * binding and AndroidKeystoreSecretStore identity, durably consumes the execution receipt, and only
 * then performs exactly one SecretStore read. Successful material is returned exclusively inside the
 * existing closeable in-memory credential lease. This phase does not read lease material, contact a
 * network, verify a remote host key, acquire SSH/SFTP, execute a remote read, mutate remote state,
 * invoke the coordinator, or expose deploy UI.
 */
internal object SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    suspend fun resolveOnce(
        receipt: SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt,
        serverAccess: ServerAccess,
        secretStore: SecretStore,
        resolvedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentRealVpsCredentialResolutionExecutionUsePort,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult {
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionHandoffConsumptionBoundary
            .validateReceipt(receipt)
        require(receipt.requiresSeparateCredentialResolutionExecutionBoundary) {
            "Real-VPS credential-resolution receipt does not require this execution boundary"
        }
        require(resolvedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "Real-VPS credential resolution cannot predate durable handoff consumption"
        }
        require(resolvedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "Real-VPS credential-resolution authorization window expired before execution"
        }
        require(serverAccess.id.value == receipt.serverAccessId) {
            "Real-VPS credential-resolution ServerAccess mismatch"
        }
        require(receipt.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name) {
            "Real-VPS credential-resolution receipt is bound to an unexpected credential store"
        }
        require(secretStore.javaClass.name == receipt.credentialStoreImplementation) {
            "Real-VPS credential-resolution SecretStore implementation identity drifted"
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == receipt.secretReferenceType) {
            "Real-VPS credential-resolution authentication reference type drifted"
        }
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        require(secretReferenceSha256 == receipt.secretReferenceSha256) {
            "Real-VPS credential-resolution SecretId reference no longer matches the reviewed hash binding"
        }
        val pinnedHostKeySha256 = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }
        val serverAccessBindingSha256 = serverAccessBindingSha256(
            serverAccess = serverAccess,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            pinnedHostKeySha256 = pinnedHostKeySha256,
        )
        require(serverAccessBindingSha256 == receipt.serverAccessBindingSha256) {
            "Real-VPS credential-resolution ServerAccess binding drifted after authorization"
        }

        require(
            executionUsePort.consumeOnce(receipt.credentialResolutionConsumptionReceiptSha256),
        ) {
            "Real-VPS credential-resolution receipt was already executed or replay fence failed closed"
        }

        val read = try {
            secretStore.read(serverAccess.auth.secretId)
        } catch (_: Throwable) {
            SecretReadResult.StorageFailure("Real-VPS credential SecretStore read threw unexpectedly")
        }

        return when (read) {
            is SecretReadResult.Found -> {
                val proof = proof(
                    status = SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus
                        .RESOLVED_TO_EPHEMERAL_LEASE,
                    receipt = receipt,
                    resolvedAtEpochMillis = resolvedAtEpochMillis,
                )
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved(
                    proof = proof,
                    lease = SiteProductionDeploymentEphemeralCredentialLease(
                        serverAccessId = receipt.serverAccessId,
                        secretReferenceType = receipt.secretReferenceType,
                        secretReferenceSha256 = receipt.secretReferenceSha256,
                        credentialResolutionConsumptionReceiptSha256 =
                            receipt.credentialResolutionConsumptionReceiptSha256,
                        resolvedAtEpochMillis = resolvedAtEpochMillis,
                        authorizationExpiresAtEpochMillis = receipt.authorizationExpiresAtEpochMillis,
                        material = read.material,
                    ),
                )
            }
            SecretReadResult.NotFound -> blocked(
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.SECRET_NOT_FOUND,
                receipt,
                resolvedAtEpochMillis,
            )
            is SecretReadResult.Unavailable -> blocked(
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.SECRET_UNAVAILABLE,
                receipt,
                resolvedAtEpochMillis,
            )
            is SecretReadResult.Corrupt -> blocked(
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.SECRET_CORRUPT,
                receipt,
                resolvedAtEpochMillis,
            )
            is SecretReadResult.StorageFailure -> blocked(
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.SECRET_STORAGE_FAILURE,
                receipt,
                resolvedAtEpochMillis,
            )
        }
    }

    fun validateProof(proof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION)
        require(proof.durableHandoffConsumed)
        require(proof.executionReceiptConsumed)
        require(proof.secretStoreReadPerformed)
        require(!proof.credentialLeaseMaterialRead)
        require(!proof.credentialMaterialPersisted)
        require(!proof.productionNetworkTouched)
        require(!proof.hostKeyPinVerifiedAgainstRemote)
        require(!proof.authorizesNetworkAccess)
        require(!proof.authorizesCredentialResolution)
        require(!proof.authorizesSshSessionAcquisition)
        require(!proof.authorizesSftpChannelOpen)
        require(!proof.authorizesReadOnlyPreflightExecution)
        require(!proof.authorizesMutation)
        require(!proof.authorizesCoordinatorInvocation)
        require(!proof.exposesDeployUiAction)
        require(!proof.realVpsAccessAllowed)
        require(proof.requiresLiveRemoteHostKeyVerification)
        require(proof.requiresSeparateSshSessionAcquisitionBoundary)
        require(proof.requiresSeparateSftpChannelOpenBoundary)
        require(proof.requiresSeparateReadOnlyExecutionBoundary)
        require(proof.requiresSeparateMutationBoundary)
        require(proof.resolvedAtEpochMillis <= proof.authorizationExpiresAtEpochMillis)
        require(proof.secretReferenceType == "password" || proof.secretReferenceType == "private-key")
        require(proof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        validateHashes(
            proof.credentialResolutionConsumptionReceiptSha256,
            proof.authorizationSha256,
            proof.handoffConsumptionReceiptSha256,
            proof.sourceAuthorizationSha256,
            proof.admissionSha256,
            proof.serverAccessBindingSha256,
            proof.requestSha256,
            proof.capabilityProfileSha256,
            proof.secretReferenceSha256,
            proof.resolutionProofSha256,
        )
        require(
            proof.resolutionProofSha256 == proofSha256(proof.copy(resolutionProofSha256 = "")),
        ) { "Real-VPS credential-resolution execution proof SHA-256 mismatch" }
    }

    private fun blocked(
        status: SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus,
        receipt: SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt,
        resolvedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Blocked =
        SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Blocked(
            proof = proof(status, receipt, resolvedAtEpochMillis),
        )

    private fun proof(
        status: SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus,
        receipt: SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt,
        resolvedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof {
        val base = SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof(
            contractVersion = CONTRACT_VERSION,
            status = status,
            durableHandoffConsumed = true,
            executionReceiptConsumed = true,
            secretStoreReadPerformed = true,
            credentialLeaseMaterialRead = false,
            credentialMaterialPersisted = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            credentialResolutionConsumptionReceiptSha256 =
                receipt.credentialResolutionConsumptionReceiptSha256,
            authorizationSha256 = receipt.authorizationSha256,
            handoffConsumptionReceiptSha256 = receipt.handoffConsumptionReceiptSha256,
            sourceAuthorizationSha256 = receipt.sourceAuthorizationSha256,
            admissionSha256 = receipt.admissionSha256,
            serverAccessBindingSha256 = receipt.serverAccessBindingSha256,
            requestSha256 = receipt.requestSha256,
            capabilityProfileSha256 = receipt.capabilityProfileSha256,
            serverAccessId = receipt.serverAccessId,
            secretReferenceType = receipt.secretReferenceType,
            secretReferenceSha256 = receipt.secretReferenceSha256,
            credentialStoreImplementation = receipt.credentialStoreImplementation,
            resolvedAtEpochMillis = resolvedAtEpochMillis,
            authorizationExpiresAtEpochMillis = receipt.authorizationExpiresAtEpochMillis,
            resolutionProofSha256 = "",
        )
        return base.copy(resolutionProofSha256 = proofSha256(base)).also(::validateProof)
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
        proof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
    ): String = sha256(
        buildString {
            append("phase=11.41\n")
            append("contractVersion=").append(proof.contractVersion).append('\n')
            append("status=").append(proof.status.name).append('\n')
            append("durableHandoffConsumed=").append(proof.durableHandoffConsumed).append('\n')
            append("executionReceiptConsumed=").append(proof.executionReceiptConsumed).append('\n')
            append("secretStoreReadPerformed=").append(proof.secretStoreReadPerformed).append('\n')
            append("credentialLeaseMaterialRead=").append(proof.credentialLeaseMaterialRead).append('\n')
            append("credentialMaterialPersisted=").append(proof.credentialMaterialPersisted).append('\n')
            append("productionNetworkTouched=").append(proof.productionNetworkTouched).append('\n')
            append("hostKeyPinVerifiedAgainstRemote=").append(proof.hostKeyPinVerifiedAgainstRemote).append('\n')
            append("authorizesNetworkAccess=").append(proof.authorizesNetworkAccess).append('\n')
            append("authorizesCredentialResolution=").append(proof.authorizesCredentialResolution).append('\n')
            append("authorizesSshSessionAcquisition=").append(proof.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(proof.authorizesSftpChannelOpen).append('\n')
            append("authorizesReadOnlyPreflightExecution=").append(proof.authorizesReadOnlyPreflightExecution).append('\n')
            append("authorizesMutation=").append(proof.authorizesMutation).append('\n')
            append("authorizesCoordinatorInvocation=").append(proof.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(proof.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(proof.realVpsAccessAllowed).append('\n')
            append("requiresLiveRemoteHostKeyVerification=")
                .append(proof.requiresLiveRemoteHostKeyVerification).append('\n')
            append("requiresSeparateSshSessionAcquisitionBoundary=")
                .append(proof.requiresSeparateSshSessionAcquisitionBoundary).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(proof.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("requiresSeparateReadOnlyExecutionBoundary=")
                .append(proof.requiresSeparateReadOnlyExecutionBoundary).append('\n')
            append("requiresSeparateMutationBoundary=")
                .append(proof.requiresSeparateMutationBoundary).append('\n')
            append("credentialResolutionConsumptionReceiptSha256=")
                .append(proof.credentialResolutionConsumptionReceiptSha256).append('\n')
            append("authorizationSha256=").append(proof.authorizationSha256).append('\n')
            append("handoffConsumptionReceiptSha256=").append(proof.handoffConsumptionReceiptSha256).append('\n')
            append("sourceAuthorizationSha256=").append(proof.sourceAuthorizationSha256).append('\n')
            append("admissionSha256=").append(proof.admissionSha256).append('\n')
            append("serverAccessBindingSha256=").append(proof.serverAccessBindingSha256).append('\n')
            append("requestSha256=").append(proof.requestSha256).append('\n')
            append("capabilityProfileSha256=").append(proof.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(proof.serverAccessId).append('\n')
            append("secretReferenceType=").append(proof.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(proof.secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(proof.credentialStoreImplementation).append('\n')
            append("resolvedAtEpochMillis=").append(proof.resolvedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=").append(proof.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS credential-resolution execution hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

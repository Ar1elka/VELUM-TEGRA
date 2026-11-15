package com.velumtegra.xuimobile.sitedeployer

import android.content.Context
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentCredentialResolutionExecutionUsePort
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import java.security.MessageDigest

/**
 * Phase 11.30 one-shot credential-resolution execution boundary.
 *
 * It validates the exact Phase 11.29 durable receipt against the exact reviewed composition,
 * ServerAccess secret reference and AndroidKeystoreSecretStore identity. It atomically consumes the
 * Phase 11.29 receipt before performing exactly one SecretStore read. A found credential is returned
 * only inside a non-persistent, closeable in-memory lease. This phase does not acquire SSH/SFTP,
 * invoke SiteDeploymentCoordinator, expose deploy UI, or access a real VPS.
 */
internal object SiteProductionDeploymentAndroidCredentialResolutionExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    suspend fun resolveOnce(
        context: Context,
        replayFence: SiteProductionDeploymentDurableReplayFence,
        receipt: SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt,
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        serverAccess: ServerAccess,
        secretStore: SecretStore,
        resolvedAtEpochMillis: Long,
        executionUsePort: SiteProductionDeploymentCredentialResolutionExecutionUsePort,
    ): SiteProductionDeploymentCredentialResolutionExecutionResult {
        SiteProductionDeploymentAndroidCredentialResolutionHandoffConsumptionBoundary
            .validateReceipt(receipt)
        require(receipt.requiresSeparateCredentialResolutionExecutionBoundary) {
            "Credential-resolution durable receipt does not require this execution boundary"
        }
        require(resolvedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "Credential resolution cannot predate durable handoff consumption"
        }
        require(resolvedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "Credential-resolution authorization window expired before execution"
        }

        val rebuiltComposition = SiteProductionDeploymentAndroidCompositionGate.prepare(
            context = context,
            replayFence = replayFence,
            serverAccess = serverAccess,
            runtimeSessionId = composition.runtimeIdentity.runtimeSessionId,
        )
        require(rebuiltComposition == composition) {
            "Credential resolution composition is stale or bound to different public identity"
        }
        require(serverAccess.id.value == composition.serverAccessId) {
            "Credential resolution ServerAccess mismatch"
        }
        require(receipt.serverAccessId == serverAccess.id.value) {
            "Credential-resolution durable receipt is bound to a different ServerAccess"
        }
        require(receipt.serverIdentitySha256 == composition.serverIdentitySha256) {
            "Credential-resolution durable receipt is bound to a different server identity"
        }
        require(receipt.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name) {
            "Credential-resolution durable receipt is bound to an unexpected credential store"
        }
        require(secretStore.javaClass.name == receipt.credentialStoreImplementation) {
            "Credential-resolution SecretStore implementation identity drifted"
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(secretReferenceType == receipt.secretReferenceType) {
            "Credential-resolution authentication reference type drifted"
        }
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        require(secretReferenceSha256 == receipt.secretReferenceSha256) {
            "Credential-resolution SecretId reference no longer matches the reviewed hash binding"
        }

        require(
            executionUsePort.consumeOnce(receipt.credentialResolutionConsumptionReceiptSha256),
        ) {
            "Credential-resolution durable receipt was already executed or replay fence failed closed"
        }

        val read = try {
            secretStore.read(serverAccess.auth.secretId)
        } catch (_: Throwable) {
            SecretReadResult.StorageFailure("Credential SecretStore read threw unexpectedly")
        }

        return when (read) {
            is SecretReadResult.Found -> {
                val proof = proof(
                    status = SiteProductionDeploymentCredentialResolutionExecutionStatus
                        .RESOLVED_TO_EPHEMERAL_LEASE,
                    receipt = receipt,
                    composition = composition,
                    resolvedAtEpochMillis = resolvedAtEpochMillis,
                )
                SiteProductionDeploymentCredentialResolutionExecutionResult.Resolved(
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
                SiteProductionDeploymentCredentialResolutionExecutionStatus.SECRET_NOT_FOUND,
                receipt,
                composition,
                resolvedAtEpochMillis,
            )
            is SecretReadResult.Unavailable -> blocked(
                SiteProductionDeploymentCredentialResolutionExecutionStatus.SECRET_UNAVAILABLE,
                receipt,
                composition,
                resolvedAtEpochMillis,
            )
            is SecretReadResult.Corrupt -> blocked(
                SiteProductionDeploymentCredentialResolutionExecutionStatus.SECRET_CORRUPT,
                receipt,
                composition,
                resolvedAtEpochMillis,
            )
            is SecretReadResult.StorageFailure -> blocked(
                SiteProductionDeploymentCredentialResolutionExecutionStatus.SECRET_STORAGE_FAILURE,
                receipt,
                composition,
                resolvedAtEpochMillis,
            )
        }
    }

    fun validateProof(proof: SiteProductionDeploymentCredentialResolutionExecutionProof) {
        require(proof.contractVersion == CONTRACT_VERSION) {
            "Unsupported credential-resolution execution contract"
        }
        require(proof.durableHandoffConsumed) {
            "Credential-resolution execution must prove durable handoff consumption"
        }
        require(proof.executionReceiptConsumed) {
            "Credential-resolution execution must prove one-shot execution-receipt consumption"
        }
        require(proof.secretStoreReadPerformed) {
            "Credential-resolution execution proof must represent exactly one SecretStore read attempt"
        }
        require(!proof.credentialMaterialPersisted) {
            "Credential-resolution execution must not persist credential material"
        }
        require(!proof.productionTransportEnabled) {
            "Credential-resolution execution must not enable production transport"
        }
        require(!proof.authorizesTransport) {
            "Credential-resolution execution must not authorize transport"
        }
        require(!proof.authorizesSshSessionAcquisition) {
            "Credential-resolution execution must not authorize SSH acquisition"
        }
        require(!proof.authorizesSftpChannelOpen) {
            "Credential-resolution execution must not authorize SFTP open"
        }
        require(!proof.authorizesCoordinatorInvocation) {
            "Credential-resolution execution must not authorize coordinator invocation"
        }
        require(!proof.exposesDeployUiAction) {
            "Credential-resolution execution must not expose deploy UI"
        }
        require(!proof.realVpsAccessAllowed) {
            "Credential-resolution execution must not permit real VPS access"
        }
        require(proof.requiresSeparateSshSessionAcquisitionBoundary) {
            "Separate SSH-session acquisition boundary must remain mandatory"
        }
        require(proof.requiresSeparateSftpChannelOpenBoundary) {
            "Separate SFTP-channel boundary must remain mandatory"
        }
        require(proof.resolvedAtEpochMillis <= proof.authorizationExpiresAtEpochMillis) {
            "Credential resolution occurred outside the authorization window"
        }
        require(proof.secretReferenceType == "password" || proof.secretReferenceType == "private-key") {
            "Credential-resolution secret reference type is invalid"
        }
        require(proof.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name) {
            "Credential-resolution credential-store implementation identity drifted"
        }
        validateHashes(
            proof.credentialResolutionConsumptionReceiptSha256,
            proof.authorizationSha256,
            proof.admissionSha256,
            proof.serverIdentitySha256,
            proof.compositionDescriptorSha256,
            proof.secretReferenceSha256,
            proof.resolutionProofSha256,
        )
        require(
            proof.resolutionProofSha256 == proofSha256(proof.copy(resolutionProofSha256 = "")),
        ) { "Credential-resolution execution proof SHA-256 mismatch" }
    }

    private fun blocked(
        status: SiteProductionDeploymentCredentialResolutionExecutionStatus,
        receipt: SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt,
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        resolvedAtEpochMillis: Long,
    ): SiteProductionDeploymentCredentialResolutionExecutionResult.Blocked =
        SiteProductionDeploymentCredentialResolutionExecutionResult.Blocked(
            proof = proof(status, receipt, composition, resolvedAtEpochMillis),
        )

    private fun proof(
        status: SiteProductionDeploymentCredentialResolutionExecutionStatus,
        receipt: SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt,
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        resolvedAtEpochMillis: Long,
    ): SiteProductionDeploymentCredentialResolutionExecutionProof {
        val base = SiteProductionDeploymentCredentialResolutionExecutionProof(
            contractVersion = CONTRACT_VERSION,
            status = status,
            durableHandoffConsumed = true,
            executionReceiptConsumed = true,
            secretStoreReadPerformed = true,
            credentialMaterialPersisted = false,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            credentialResolutionConsumptionReceiptSha256 =
                receipt.credentialResolutionConsumptionReceiptSha256,
            authorizationSha256 = receipt.authorizationSha256,
            admissionSha256 = receipt.admissionSha256,
            serverIdentitySha256 = receipt.serverIdentitySha256,
            compositionDescriptorSha256 = composition.descriptorSha256,
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

    private fun proofSha256(
        proof: SiteProductionDeploymentCredentialResolutionExecutionProof,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(proof.contractVersion).append('\n')
            append("status=").append(proof.status.name).append('\n')
            append("durableHandoffConsumed=").append(proof.durableHandoffConsumed).append('\n')
            append("executionReceiptConsumed=").append(proof.executionReceiptConsumed).append('\n')
            append("secretStoreReadPerformed=").append(proof.secretStoreReadPerformed).append('\n')
            append("credentialMaterialPersisted=").append(proof.credentialMaterialPersisted).append('\n')
            append("productionTransportEnabled=").append(proof.productionTransportEnabled).append('\n')
            append("authorizesTransport=").append(proof.authorizesTransport).append('\n')
            append("authorizesSshSessionAcquisition=").append(proof.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(proof.authorizesSftpChannelOpen).append('\n')
            append("authorizesCoordinatorInvocation=").append(proof.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(proof.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(proof.realVpsAccessAllowed).append('\n')
            append("requiresSeparateSshSessionAcquisitionBoundary=")
                .append(proof.requiresSeparateSshSessionAcquisitionBoundary).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(proof.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("credentialResolutionConsumptionReceiptSha256=")
                .append(proof.credentialResolutionConsumptionReceiptSha256).append('\n')
            append("authorizationSha256=").append(proof.authorizationSha256).append('\n')
            append("admissionSha256=").append(proof.admissionSha256).append('\n')
            append("serverIdentitySha256=").append(proof.serverIdentitySha256).append('\n')
            append("compositionDescriptorSha256=").append(proof.compositionDescriptorSha256).append('\n')
            append("serverAccessId=").append(proof.serverAccessId).append('\n')
            append("secretReferenceType=").append(proof.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(proof.secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(proof.credentialStoreImplementation).append('\n')
            append("resolvedAtEpochMillis=").append(proof.resolvedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=").append(proof.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256::matches)) {
            "Credential-resolution execution hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

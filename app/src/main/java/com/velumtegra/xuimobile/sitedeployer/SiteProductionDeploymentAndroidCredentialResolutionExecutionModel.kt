package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.domain.SecretMaterial
import java.util.concurrent.atomic.AtomicBoolean

enum class SiteProductionDeploymentCredentialResolutionExecutionStatus {
    RESOLVED_TO_EPHEMERAL_LEASE,
    SECRET_NOT_FOUND,
    SECRET_UNAVAILABLE,
    SECRET_CORRUPT,
    SECRET_STORAGE_FAILURE,
}

data class SiteProductionDeploymentCredentialResolutionExecutionProof(
    val contractVersion: Int,
    val status: SiteProductionDeploymentCredentialResolutionExecutionStatus,
    val durableHandoffConsumed: Boolean,
    val executionReceiptConsumed: Boolean,
    val secretStoreReadPerformed: Boolean,
    val credentialMaterialPersisted: Boolean,
    val productionTransportEnabled: Boolean,
    val authorizesTransport: Boolean,
    val authorizesSshSessionAcquisition: Boolean,
    val authorizesSftpChannelOpen: Boolean,
    val authorizesCoordinatorInvocation: Boolean,
    val exposesDeployUiAction: Boolean,
    val realVpsAccessAllowed: Boolean,
    val requiresSeparateSshSessionAcquisitionBoundary: Boolean,
    val requiresSeparateSftpChannelOpenBoundary: Boolean,
    val credentialResolutionConsumptionReceiptSha256: String,
    val authorizationSha256: String,
    val admissionSha256: String,
    val serverIdentitySha256: String,
    val compositionDescriptorSha256: String,
    val serverAccessId: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val credentialStoreImplementation: String,
    val resolvedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    val resolutionProofSha256: String,
)

sealed interface SiteProductionDeploymentCredentialResolutionExecutionResult {
    val proof: SiteProductionDeploymentCredentialResolutionExecutionProof

    data class Resolved(
        override val proof: SiteProductionDeploymentCredentialResolutionExecutionProof,
        val lease: SiteProductionDeploymentEphemeralCredentialLease,
    ) : SiteProductionDeploymentCredentialResolutionExecutionResult

    data class Blocked(
        override val proof: SiteProductionDeploymentCredentialResolutionExecutionProof,
    ) : SiteProductionDeploymentCredentialResolutionExecutionResult
}

/**
 * In-memory only owner for one resolved credential. Material can be used once by a later reviewed
 * boundary and is always closed after that use. This object is not serializable and never renders
 * credential bytes in toString().
 */
class SiteProductionDeploymentEphemeralCredentialLease internal constructor(
    val serverAccessId: String,
    val secretReferenceType: String,
    val secretReferenceSha256: String,
    val credentialResolutionConsumptionReceiptSha256: String,
    val resolvedAtEpochMillis: Long,
    val authorizationExpiresAtEpochMillis: Long,
    private var material: SecretMaterial?,
) : AutoCloseable {
    private val used = AtomicBoolean(false)
    private val monitor = Any()

    suspend fun <T> useMaterialOnce(block: suspend (SecretMaterial) -> T): T {
        check(used.compareAndSet(false, true)) { "Credential lease was already used or closed" }
        val owned = synchronized(monitor) {
            val current = material ?: error("Credential lease material is unavailable")
            material = null
            current
        }
        return try {
            block(owned)
        } finally {
            owned.close()
        }
    }

    override fun close() {
        used.set(true)
        val owned = synchronized(monitor) {
            val current = material
            material = null
            current
        }
        owned?.close()
    }

    override fun toString(): String =
        "SiteProductionDeploymentEphemeralCredentialLease(" +
            "serverAccessId=$serverAccessId, secretReferenceType=$secretReferenceType, " +
            "secretReferenceSha256=$secretReferenceSha256, " +
            "credentialResolutionConsumptionReceiptSha256=$credentialResolutionConsumptionReceiptSha256, " +
            "material=[REDACTED])"
}

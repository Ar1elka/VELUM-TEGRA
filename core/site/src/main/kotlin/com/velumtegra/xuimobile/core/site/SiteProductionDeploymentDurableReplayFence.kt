package com.velumtegra.xuimobile.core.site

import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * Process-restart durable consume-once fence for production deployment approvals.
 *
 * The marker create operation is the authorization point. Once a marker path exists, even if its
 * optional metadata is empty/corrupt because a process stopped immediately after creation, recovery
 * treats the digest as consumed. This intentionally fails closed and never deletes replay markers.
 */
class SiteProductionDeploymentDurableReplayFence private constructor(
    private val canonicalRoot: File,
) {
    companion object {
        const val CONTRACT_VERSION: Int = 1
        private val sha256 = Regex("^[0-9a-f]{64}$")
        private const val MARKER_SUFFIX = ".consumed"

        fun open(root: File): SiteProductionDeploymentDurableReplayFence {
            require(root.path.isNotBlank()) { "Replay fence root path must not be blank" }
            if (root.exists()) {
                require(root.isDirectory) { "Replay fence root must be a directory" }
            } else {
                require(root.mkdirs() || root.isDirectory) { "Replay fence root cannot be created" }
            }
            val canonical = try {
                root.canonicalFile
            } catch (error: IOException) {
                throw IllegalArgumentException("Replay fence root cannot be canonicalized", error)
            }
            require(canonical.isDirectory) { "Replay fence canonical root must be a directory" }
            return SiteProductionDeploymentDurableReplayFence(canonical)
        }
    }

    fun runtimeMutationConsumptionPort(): SiteProductionDeploymentRuntimeMutationConsumptionPort =
        SiteProductionDeploymentRuntimeMutationConsumptionPort { permitSha256 ->
            consumeOnce(SiteProductionDeploymentReplayScope.RUNTIME_MUTATION_PERMIT, permitSha256)
        }

    fun coordinatorInvocationUsePort(): SiteProductionDeploymentCoordinatorInvocationUsePort =
        SiteProductionDeploymentCoordinatorInvocationUsePort { invocationAuthorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.COORDINATOR_INVOCATION_AUTHORIZATION,
                invocationAuthorizationSha256,
            )
        }


    fun transportAcquisitionHandoffConsumptionPort():
        SiteProductionDeploymentTransportAcquisitionHandoffConsumptionPort =
        SiteProductionDeploymentTransportAcquisitionHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.TRANSPORT_ACQUISITION_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }

    fun credentialResolutionHandoffConsumptionPort():
        SiteProductionDeploymentCredentialResolutionHandoffConsumptionPort =
        SiteProductionDeploymentCredentialResolutionHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }

    fun credentialResolutionExecutionUsePort():
        SiteProductionDeploymentCredentialResolutionExecutionUsePort =
        SiteProductionDeploymentCredentialResolutionExecutionUsePort {
                credentialResolutionConsumptionReceiptSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
                credentialResolutionConsumptionReceiptSha256,
            )
        }

    fun sshSessionAcquisitionHandoffConsumptionPort():
        SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionPort =
        SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }

    fun sftpChannelOpenHandoffConsumptionPort():
        SiteProductionDeploymentSftpChannelOpenHandoffConsumptionPort =
        SiteProductionDeploymentSftpChannelOpenHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }


    fun sftpReadOnlyPreflightHandoffConsumptionPort():
        SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionPort =
        SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }


    fun realVpsReadOnlyPreflightHandoffConsumptionPort():
        SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionPort =
        SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }


    fun realVpsCredentialResolutionHandoffConsumptionPort():
        SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionPort =
        SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }

    fun realVpsCredentialResolutionExecutionUsePort():
        SiteProductionDeploymentRealVpsCredentialResolutionExecutionUsePort =
        SiteProductionDeploymentRealVpsCredentialResolutionExecutionUsePort { receiptSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
                receiptSha256,
            )
        }

    fun realVpsSshSessionAcquisitionHandoffConsumptionPort():
        SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionPort =
        SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }


    fun realVpsSshSessionAcquisitionExecutionUsePort():
        SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionUsePort =
        SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionUsePort { receiptSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_RECEIPT,
                receiptSha256,
            )
        }


    fun realVpsSftpChannelOpenHandoffConsumptionPort():
        SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionPort =
        SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }

    fun realVpsSftpChannelOpenExecutionUsePort():
        SiteProductionDeploymentRealVpsSftpChannelOpenExecutionUsePort =
        SiteProductionDeploymentRealVpsSftpChannelOpenExecutionUsePort { receiptSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_EXECUTION_RECEIPT,
                receiptSha256,
            )
        }

    fun realVpsSftpReadOnlyPreflightHandoffConsumptionPort():
        SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionPort =
        SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionPort { authorizationSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                authorizationSha256,
            )
        }

    fun realVpsSftpReadOnlyPreflightExecutionUsePort():
        SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionUsePort =
        SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionUsePort { receiptSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_EXECUTION_RECEIPT,
                receiptSha256,
            )
        }

    fun realVpsStagingWriteExecutionUsePort():
        SiteProductionDeploymentRealVpsStagingWriteExecutionUsePort =
        SiteProductionDeploymentRealVpsStagingWriteExecutionUsePort { stagingWritePlanSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_STAGING_WRITE_EXECUTION_RECEIPT,
                stagingWritePlanSha256,
            )
        }

    fun realVpsCommitTransactionExecutionUsePort():
        SiteProductionDeploymentRealVpsCommitTransactionExecutionUsePort =
        SiteProductionDeploymentRealVpsCommitTransactionExecutionUsePort { commitTransactionPlanSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_COMMIT_TRANSACTION_EXECUTION_RECEIPT,
                commitTransactionPlanSha256,
            )
        }

    fun realVpsPostTransactionCleanupExecutionUsePort():
        SiteProductionDeploymentRealVpsPostTransactionCleanupExecutionUsePort =
        SiteProductionDeploymentRealVpsPostTransactionCleanupExecutionUsePort { cleanupPlanSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_POST_TRANSACTION_CLEANUP_EXECUTION_RECEIPT,
                cleanupPlanSha256,
            )
        }

    fun realVpsWebServingConfigStagingSyntaxExecutionUsePort():
        SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionUsePort =
        SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionUsePort { executionPlanSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_CONFIG_STAGING_SYNTAX_EXECUTION_RECEIPT,
                executionPlanSha256,
            )
        }

    fun realVpsWebServingRuntimeProvisioningExecutionUsePort():
        SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionUsePort =
        SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionUsePort { provisioningPlanSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_RUNTIME_PROVISIONING_EXECUTION_RECEIPT,
                provisioningPlanSha256,
            )
        }

    fun realVpsWebServingConfigActivationExecutionUsePort():
        SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort =
        SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort { activationPlanSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_CONFIG_ACTIVATION_EXECUTION_RECEIPT,
                activationPlanSha256,
            )
        }

    fun realVpsWebServingNginxReloadExecutionUsePort():
        SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort =
        SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort { reloadPlanSha256 ->
            consumeOnce(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_NGINX_RELOAD_EXECUTION_RECEIPT,
                reloadPlanSha256,
            )
        }

    fun hasConsumed(scope: SiteProductionDeploymentReplayScope, digestSha256: String): Boolean {
        validateDigest(digestSha256)
        return try {
            markerFile(scope, digestSha256).exists()
        } catch (_: IOException) {
            true
        }
    }

    fun snapshot(): SiteProductionDeploymentReplayFenceSnapshot =
        SiteProductionDeploymentReplayFenceSnapshot(
            contractVersion = CONTRACT_VERSION,
            canonicalRootPath = canonicalRoot.path,
            runtimeMutationPermitMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.RUNTIME_MUTATION_PERMIT,
            ),
            coordinatorInvocationAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.COORDINATOR_INVOCATION_AUTHORIZATION,
            ),
            transportAcquisitionHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.TRANSPORT_ACQUISITION_HANDOFF_AUTHORIZATION,
            ),
            credentialResolutionHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
            ),
            credentialResolutionExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
            ),
            sshSessionAcquisitionHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
            ),
            sftpChannelOpenHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
            ),
            sftpReadOnlyPreflightHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
            ),
            realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
            ),
            realVpsCredentialResolutionHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
            ),
            realVpsCredentialResolutionExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
            ),
            realVpsSshSessionAcquisitionHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
            ),
            realVpsSshSessionAcquisitionExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_RECEIPT,
            ),
            realVpsSftpChannelOpenHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
            ),
            realVpsSftpChannelOpenExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_EXECUTION_RECEIPT,
            ),
            realVpsSftpReadOnlyPreflightHandoffAuthorizationMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
            ),
            realVpsSftpReadOnlyPreflightExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_EXECUTION_RECEIPT,
            ),
            realVpsStagingWriteExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_STAGING_WRITE_EXECUTION_RECEIPT,
            ),
            realVpsCommitTransactionExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_COMMIT_TRANSACTION_EXECUTION_RECEIPT,
            ),
            realVpsPostTransactionCleanupExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_POST_TRANSACTION_CLEANUP_EXECUTION_RECEIPT,
            ),
            realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_CONFIG_STAGING_SYNTAX_EXECUTION_RECEIPT,
            ),
            realVpsWebServingRuntimeProvisioningExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_RUNTIME_PROVISIONING_EXECUTION_RECEIPT,
            ),
            realVpsWebServingConfigActivationExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_CONFIG_ACTIVATION_EXECUTION_RECEIPT,
            ),
            realVpsWebServingNginxReloadExecutionReceiptMarkerCount = markerCount(
                SiteProductionDeploymentReplayScope.REAL_VPS_WEB_SERVING_NGINX_RELOAD_EXECUTION_RECEIPT,
            ),
        )

    private fun consumeOnce(
        scope: SiteProductionDeploymentReplayScope,
        digestSha256: String,
    ): Boolean {
        validateDigest(digestSha256)
        val marker = try {
            markerFile(scope, digestSha256)
        } catch (_: IOException) {
            return false
        }

        // File.createNewFile() performs an atomic check-and-create. This remains the cross-process
        // arbiter even when two fence instances race after an application restart.
        val created = try {
            marker.createNewFile()
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
        if (!created) return false

        // Metadata is diagnostic only. The existence of the marker is authoritative. If metadata
        // persistence fails we return false, leaving the marker in place so recovery cannot replay.
        return try {
            FileOutputStream(marker, true).use { output ->
                val payload = buildString {
                    append("contractVersion=").append(CONTRACT_VERSION).append('\n')
                    append("scope=").append(scope.name).append('\n')
                    append("sha256=").append(digestSha256).append('\n')
                }.encodeToByteArray()
                output.write(payload)
                output.flush()
                output.fd.sync()
            }
            true
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    @Throws(IOException::class)
    private fun markerFile(
        scope: SiteProductionDeploymentReplayScope,
        digestSha256: String,
    ): File {
        val namespace = namespaceDirectory(scope)
        val marker = File(namespace, "$digestSha256$MARKER_SUFFIX").canonicalFile
        require(marker.parentFile == namespace) { "Replay marker escaped its exact namespace" }
        return marker
    }

    @Throws(IOException::class)
    private fun namespaceDirectory(scope: SiteProductionDeploymentReplayScope): File {
        val namespace = File(canonicalRoot, scope.directoryName)
        if (namespace.exists()) {
            if (!namespace.isDirectory) throw IOException("Replay namespace is not a directory")
        } else if (!namespace.mkdirs() && !namespace.isDirectory) {
            throw IOException("Replay namespace cannot be created")
        }
        val canonicalNamespace = namespace.canonicalFile
        if (canonicalNamespace.parentFile != canonicalRoot) {
            throw IOException("Replay namespace escaped canonical root")
        }
        return canonicalNamespace
    }

    private fun markerCount(scope: SiteProductionDeploymentReplayScope): Int = try {
        val namespace = namespaceDirectory(scope)
        namespace.listFiles { file ->
            file.isFile && file.name.endsWith(MARKER_SUFFIX) &&
                sha256.matches(file.name.removeSuffix(MARKER_SUFFIX))
        }?.size ?: 0
    } catch (_: IOException) {
        -1
    } catch (_: SecurityException) {
        -1
    }

    private fun validateDigest(digestSha256: String) {
        require(sha256.matches(digestSha256)) { "Replay fence digest must be lowercase SHA-256" }
    }
}

package com.velumtegra.xuimobile.sitedeployer

import android.content.Context
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPolicy
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSshDeploymentRuntime
import java.security.MessageDigest

/**
 * Phase 11.27 non-executing admission boundary.
 *
 * It proves that the durably consumed Phase 11.26 handoff is still bound to the exact reviewed
 * Android composition plus the existing runtime/SSH/SFTP implementation identities. It does not
 * instantiate the runtime graph, resolve a secret, connect SSH, open SFTP, invoke the coordinator,
 * expose deploy UI, or contact a real VPS.
 */
internal object SiteProductionDeploymentAndroidTransportAcquisitionExecutionAdmissionBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun prepare(
        context: Context,
        replayFence: SiteProductionDeploymentDurableReplayFence,
        receipt: SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt,
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        serverAccess: ServerAccess,
        evaluatedAtEpochMillis: Long,
    ): SiteProductionDeploymentTransportAcquisitionExecutionAdmission {
        SiteProductionDeploymentAndroidTransportAcquisitionHandoffConsumptionBoundary.validateReceipt(receipt)
        require(evaluatedAtEpochMillis >= receipt.consumedAtEpochMillis) {
            "Transport-acquisition execution admission cannot predate durable handoff consumption"
        }

        val rebuiltComposition = SiteProductionDeploymentAndroidCompositionGate.prepare(
            context = context,
            replayFence = replayFence,
            serverAccess = serverAccess,
            runtimeSessionId = composition.runtimeIdentity.runtimeSessionId,
        )
        require(rebuiltComposition == composition) {
            "Transport-acquisition execution admission composition is stale or bound to different public identity"
        }
        require(receipt.compositionDescriptorSha256 == composition.descriptorSha256) {
            "Durable handoff receipt is bound to a different production composition"
        }
        require(receipt.serverIdentitySha256 == composition.serverIdentitySha256) {
            "Durable handoff receipt is bound to a different server identity"
        }
        require(receipt.runtimeSessionId == composition.runtimeIdentity.runtimeSessionId) {
            "Durable handoff receipt is bound to a different runtime session identity"
        }
        require(receipt.remoteHostIdentity == composition.runtimeIdentity.remoteHostIdentity) {
            "Durable handoff receipt is bound to a different remote host identity"
        }
        require(receipt.boundedSftpImplementationId == composition.runtimeIdentity.transportImplementationId) {
            "Durable handoff receipt is bound to a different transport implementation"
        }
        require(
            receipt.boundedSftpCapabilityProfileSha256 ==
                composition.runtimeIdentity.capabilityProfileSha256,
        ) {
            "Durable handoff receipt is bound to a different transport capability profile"
        }
        require(receipt.singleUseConsumed) {
            "Transport-acquisition execution admission requires durable handoff consumption"
        }
        require(receipt.requiresSeparateAcquisitionExecutionBoundary) {
            "Transport-acquisition execution admission must remain a separate boundary"
        }

        val capabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES
        SiteRemoteTransportPolicy.validateCapabilities(capabilities)
        val capabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities)
        require(receipt.boundedSftpImplementationId == capabilities.implementationId) {
            "Durable handoff receipt no longer matches the exact bounded SFTP implementation"
        }
        require(receipt.boundedSftpCapabilityProfileSha256 == capabilityProfileSha256) {
            "Durable handoff receipt no longer matches the exact bounded SFTP capability profile"
        }

        val pinnedHostKeySha256 = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }
        require(pinnedHostKeySha256 == composition.pinnedHostKeySha256) {
            "Transport-acquisition execution admission host-key identity mismatch"
        }
        require(serverAccess.id.value == composition.serverAccessId) {
            "Transport-acquisition execution admission ServerAccess mismatch"
        }
        require(serverAccess.endpoint.host == composition.sshHost) {
            "Transport-acquisition execution admission SSH host mismatch"
        }
        require(serverAccess.endpoint.port == composition.sshPort) {
            "Transport-acquisition execution admission SSH port mismatch"
        }

        val blockers = buildList {
            if (evaluatedAtEpochMillis > receipt.authorizationExpiresAtEpochMillis) {
                add(
                    SiteProductionDeploymentTransportAcquisitionExecutionAdmissionBlocker(
                        code = "TRANSPORT_ACQUISITION_AUTHORIZATION_WINDOW_EXPIRED",
                        detail = "Durably consumed transport-acquisition handoff is outside its authorization window",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus
                .ADMITTED_FOR_SEPARATE_TRANSPORT_ACQUISITION_EXECUTION_BOUNDARY
        } else {
            SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus.BLOCKED
        }

        val base = SiteProductionDeploymentTransportAcquisitionExecutionAdmission(
            contractVersion = CONTRACT_VERSION,
            status = status,
            admissionOnly = true,
            durableHandoffConsumed = true,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesTransportAcquisitionExecution = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresSeparateCredentialResolutionBoundary = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            consumptionReceiptSha256 = receipt.consumptionReceiptSha256,
            authorizationSha256 = receipt.authorizationSha256,
            readinessSha256 = receipt.readinessSha256,
            compositionDescriptorSha256 = receipt.compositionDescriptorSha256,
            serverIdentitySha256 = receipt.serverIdentitySha256,
            runtimeSessionId = receipt.runtimeSessionId,
            remoteHostIdentity = receipt.remoteHostIdentity,
            serverAccessId = composition.serverAccessId,
            pinnedHostKeySha256 = composition.pinnedHostKeySha256,
            runtimeCoordinatorImplementation = OperationRuntimeCoordinator::class.java.name,
            sshConnectionFactoryImplementation = JschSshConnectionFactory::class.java.name,
            exactSessionRegistryImplementation = ExactSessionRegistry::class.java.name,
            deploymentRuntimeImplementation = SiteRemoteSshDeploymentRuntime::class.java.name,
            sftpPrimitiveFactoryImplementation = SiteRemoteSftpPrimitiveFactory::class.java.name,
            boundedSftpImplementationId = capabilities.implementationId,
            boundedSftpCapabilityProfileSha256 = capabilityProfileSha256,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = receipt.authorizationExpiresAtEpochMillis,
            blockers = blockers,
            admissionSha256 = "",
        )
        return base.copy(
            admissionSha256 = admissionSha256(base),
        ).also(::validate)
    }

    fun validate(admission: SiteProductionDeploymentTransportAcquisitionExecutionAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION) {
            "Unsupported transport-acquisition execution admission contract"
        }
        require(admission.admissionOnly) {
            "Transport-acquisition execution admission must remain admission-only"
        }
        require(admission.durableHandoffConsumed) {
            "Transport-acquisition execution admission must prove durable handoff consumption"
        }
        require(!admission.productionTransportEnabled) {
            "Transport-acquisition execution admission must not enable production transport"
        }
        require(!admission.authorizesTransport) {
            "Transport-acquisition execution admission must not authorize transport"
        }
        require(!admission.authorizesTransportAcquisitionExecution) {
            "Transport-acquisition execution admission must not authorize acquisition execution"
        }
        require(!admission.authorizesCredentialResolution) {
            "Transport-acquisition execution admission must not authorize credential resolution"
        }
        require(!admission.authorizesSshSessionAcquisition) {
            "Transport-acquisition execution admission must not authorize SSH acquisition"
        }
        require(!admission.authorizesSftpChannelOpen) {
            "Transport-acquisition execution admission must not authorize SFTP open"
        }
        require(!admission.authorizesCoordinatorInvocation) {
            "Transport-acquisition execution admission must not authorize coordinator invocation"
        }
        require(!admission.exposesDeployUiAction) {
            "Transport-acquisition execution admission must not expose deploy UI"
        }
        require(!admission.realVpsAccessAllowed) {
            "Transport-acquisition execution admission must not permit real VPS access"
        }
        require(admission.requiresSeparateCredentialResolutionBoundary) {
            "Separate credential-resolution boundary must remain mandatory"
        }
        require(admission.requiresSeparateSshSessionAcquisitionBoundary) {
            "Separate SSH-session acquisition boundary must remain mandatory"
        }
        require(admission.requiresSeparateSftpChannelOpenBoundary) {
            "Separate SFTP-channel boundary must remain mandatory"
        }
        val expectedStatus = if (admission.blockers.isEmpty()) {
            SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus
                .ADMITTED_FOR_SEPARATE_TRANSPORT_ACQUISITION_EXECUTION_BOUNDARY
        } else {
            SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus.BLOCKED
        }
        require(admission.status == expectedStatus) {
            "Transport-acquisition execution admission status does not match blockers"
        }
        validateHashes(
            admission.consumptionReceiptSha256,
            admission.authorizationSha256,
            admission.readinessSha256,
            admission.compositionDescriptorSha256,
            admission.serverIdentitySha256,
            admission.pinnedHostKeySha256,
            admission.boundedSftpCapabilityProfileSha256,
            admission.admissionSha256,
        )
        require(
            admission.runtimeCoordinatorImplementation == OperationRuntimeCoordinator::class.java.name,
        ) { "Runtime coordinator implementation identity drifted" }
        require(
            admission.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name,
        ) { "SSH connection factory implementation identity drifted" }
        require(
            admission.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name,
        ) { "Exact-session registry implementation identity drifted" }
        require(
            admission.deploymentRuntimeImplementation == SiteRemoteSshDeploymentRuntime::class.java.name,
        ) { "Site deployment runtime implementation identity drifted" }
        require(
            admission.sftpPrimitiveFactoryImplementation == SiteRemoteSftpPrimitiveFactory::class.java.name,
        ) { "Bounded SFTP primitive factory implementation identity drifted" }
        require(
            admission.boundedSftpImplementationId == SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId,
        ) { "Bounded SFTP implementation id drifted" }
        require(
            admission.boundedSftpCapabilityProfileSha256 ==
                SiteRemoteTransportPolicy.capabilityProfileSha256(SiteRemoteSftpPrimitiveFactory.CAPABILITIES),
        ) { "Bounded SFTP capability profile drifted" }
        require(
            admission.admissionSha256 ==
                admissionSha256(admission.copy(admissionSha256 = "")),
        ) { "Transport-acquisition execution admission SHA-256 mismatch" }
    }

    private fun admissionSha256(
        admission: SiteProductionDeploymentTransportAcquisitionExecutionAdmission,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(admission.contractVersion).append('\n')
            append("status=").append(admission.status.name).append('\n')
            append("admissionOnly=").append(admission.admissionOnly).append('\n')
            append("durableHandoffConsumed=").append(admission.durableHandoffConsumed).append('\n')
            append("productionTransportEnabled=").append(admission.productionTransportEnabled).append('\n')
            append("authorizesTransport=").append(admission.authorizesTransport).append('\n')
            append("authorizesTransportAcquisitionExecution=")
                .append(admission.authorizesTransportAcquisitionExecution).append('\n')
            append("authorizesCredentialResolution=").append(admission.authorizesCredentialResolution).append('\n')
            append("authorizesSshSessionAcquisition=").append(admission.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(admission.authorizesSftpChannelOpen).append('\n')
            append("authorizesCoordinatorInvocation=").append(admission.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(admission.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(admission.realVpsAccessAllowed).append('\n')
            append("requiresSeparateCredentialResolutionBoundary=")
                .append(admission.requiresSeparateCredentialResolutionBoundary).append('\n')
            append("requiresSeparateSshSessionAcquisitionBoundary=")
                .append(admission.requiresSeparateSshSessionAcquisitionBoundary).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(admission.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("consumptionReceiptSha256=").append(admission.consumptionReceiptSha256).append('\n')
            append("authorizationSha256=").append(admission.authorizationSha256).append('\n')
            append("readinessSha256=").append(admission.readinessSha256).append('\n')
            append("compositionDescriptorSha256=").append(admission.compositionDescriptorSha256).append('\n')
            append("serverIdentitySha256=").append(admission.serverIdentitySha256).append('\n')
            append("runtimeSessionId=").append(admission.runtimeSessionId).append('\n')
            append("remoteHostIdentity=").append(admission.remoteHostIdentity).append('\n')
            append("serverAccessId=").append(admission.serverAccessId).append('\n')
            append("pinnedHostKeySha256=").append(admission.pinnedHostKeySha256).append('\n')
            append("runtimeCoordinatorImplementation=").append(admission.runtimeCoordinatorImplementation).append('\n')
            append("sshConnectionFactoryImplementation=").append(admission.sshConnectionFactoryImplementation).append('\n')
            append("exactSessionRegistryImplementation=").append(admission.exactSessionRegistryImplementation).append('\n')
            append("deploymentRuntimeImplementation=").append(admission.deploymentRuntimeImplementation).append('\n')
            append("sftpPrimitiveFactoryImplementation=").append(admission.sftpPrimitiveFactoryImplementation).append('\n')
            append("boundedSftpImplementationId=").append(admission.boundedSftpImplementationId).append('\n')
            append("boundedSftpCapabilityProfileSha256=")
                .append(admission.boundedSftpCapabilityProfileSha256).append('\n')
            append("evaluatedAtEpochMillis=").append(admission.evaluatedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=")
                .append(admission.authorizationExpiresAtEpochMillis).append('\n')
            admission.blockers.forEach { blocker ->
                append("blocker=").append(blocker.code).append('\u0000').append(blocker.detail).append('\n')
            }
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256::matches)) {
            "Transport-acquisition execution admission hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

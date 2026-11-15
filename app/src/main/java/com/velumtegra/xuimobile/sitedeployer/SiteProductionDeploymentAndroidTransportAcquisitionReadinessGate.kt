package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationApproval
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationBoundary
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPolicy
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import java.security.MessageDigest

/**
 * Non-executing gate immediately before any future production transport acquisition path.
 *
 * It revalidates the exact Phase 11.23 Android composition, currently-fresh readiness/execution
 * evidence, the exact runtime-mutation permit, and the exact reviewed bounded-SFTP implementation.
 * It deliberately has no secret store, SSH connection factory, session registry, SFTP channel,
 * SiteDeploymentCoordinator, or UI dependency.
 */
internal object SiteProductionDeploymentAndroidTransportAcquisitionReadinessGate {
    const val CONTRACT_VERSION: Int = 1

    fun prepare(
        request: SiteProductionDeploymentTransportAcquisitionReadinessRequest,
    ): SiteProductionDeploymentTransportAcquisitionReadinessDescriptor {
        require(request.evaluatedAtEpochMillis >= 0L) { "Transport-acquisition readiness time must be non-negative" }

        SiteProductionDeploymentAndroidCompositionGate.validate(request.composition)
        SiteProductionDeploymentExecutionBoundary.validateForCoordinatorHandoff(
            request.executionAuthorization,
            request.executionRequest,
        )
        require(request.runtimeMutationRequest.executionAuthorization == request.executionAuthorization) {
            "Runtime-mutation request is bound to a different execution authorization"
        }
        require(request.runtimeMutationRequest.executionRequest == request.executionRequest) {
            "Runtime-mutation request is bound to different execution inputs"
        }

        val rebuiltRuntimeDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(
            request.runtimeMutationRequest,
        )
        val rebuiltPermit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            rebuiltRuntimeDraft,
            SiteProductionDeploymentRuntimeMutationApproval(
                runtimeMutationApprovalChallengeSha256 = rebuiltRuntimeDraft.runtimeMutationApprovalChallengeSha256,
                confirmed = true,
            ),
        )
        require(rebuiltPermit == request.runtimeMutationPermit) {
            "Runtime-mutation permit is stale, tampered, or bound to different current evidence"
        }

        val capabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES
        val capabilitySha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities)
        require(request.executionRequest.transportCapabilities == capabilities) {
            "Execution evidence is not bound to the exact production bounded-SFTP capability profile"
        }
        require(request.executionAuthorization.capabilityProfileSha256 == capabilitySha256) {
            "Execution authorization capability digest differs from production bounded-SFTP"
        }
        require(request.runtimeMutationPermit.capabilityProfileSha256 == capabilitySha256) {
            "Runtime-mutation permit capability digest differs from production bounded-SFTP"
        }
        require(request.composition.runtimeIdentity.transportImplementationId == capabilities.implementationId) {
            "Composition transport implementation differs from production bounded-SFTP"
        }
        require(request.composition.runtimeIdentity.capabilityProfileSha256 == capabilitySha256) {
            "Composition capability digest differs from production bounded-SFTP"
        }
        require(request.runtimeMutationRequest.runtimeIdentity == request.composition.runtimeIdentity) {
            "Runtime identity differs from the reviewed Android production composition"
        }
        require(request.composition.remoteHostIdentityOrThrow() == request.executionRequest.readyRecord.remoteHostIdentity) {
            "Composition host differs from the approved production host"
        }
        require(request.runtimeMutationPermit.candidateTransportAuthorizationSha256 ==
            request.executionAuthorization.candidateTransportAuthorizationSha256
        ) { "Candidate transport authorization changed between execution and runtime mutation gates" }
        require(request.evaluatedAtEpochMillis >= request.runtimeMutationPermit.evaluatedAtEpochMillis) {
            "Transport-acquisition readiness cannot predate runtime-mutation permit evaluation"
        }

        val blockers = buildList {
            if (request.evaluatedAtEpochMillis > request.executionAuthorization.evidenceExpiresAtEpochMillis) {
                add(
                    SiteProductionDeploymentTransportAcquisitionReadinessBlocker(
                        code = "EXECUTION_EVIDENCE_STALE",
                        detail = "Approved readiness/execution evidence expired before transport-acquisition readiness",
                    ),
                )
            }
            if (request.evaluatedAtEpochMillis > request.runtimeMutationPermit.permitExpiresAtEpochMillis) {
                add(
                    SiteProductionDeploymentTransportAcquisitionReadinessBlocker(
                        code = "RUNTIME_MUTATION_PERMIT_EXPIRED",
                        detail = "Runtime-mutation permit expired before transport-acquisition readiness",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentTransportAcquisitionReadinessStatus.READY_FOR_SEPARATE_TRANSPORT_ACQUISITION
        } else {
            SiteProductionDeploymentTransportAcquisitionReadinessStatus.BLOCKED
        }

        val base = SiteProductionDeploymentTransportAcquisitionReadinessDescriptor(
            contractVersion = CONTRACT_VERSION,
            status = status,
            readinessOnly = true,
            productionTransportEnabled = false,
            authorizesTransport = false,
            resolvesCredentials = false,
            acquiresSshSession = false,
            opensSftpChannel = false,
            invokesCoordinator = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresSeparateTransportAcquisitionAuthorization = true,
            requiresDurableReplayConsumptionBeforeCoordinatorInvocation = true,
            compositionDescriptorSha256 = request.composition.descriptorSha256,
            serverIdentitySha256 = request.composition.serverIdentitySha256,
            runtimeSessionId = request.composition.runtimeIdentity.runtimeSessionId,
            remoteHostIdentity = request.composition.runtimeIdentity.remoteHostIdentity,
            executionAttemptId = request.executionAuthorization.executionAttemptId,
            coordinatorInvocationId = request.runtimeMutationPermit.coordinatorInvocationId,
            readyRecordSha256 = request.executionAuthorization.readyRecordSha256,
            executionAuthorizationSha256 = request.executionAuthorization.executionAuthorizationSha256,
            runtimeMutationPermitSha256 = request.runtimeMutationPermit.permitSha256,
            runtimeIdentitySha256 = request.runtimeMutationPermit.runtimeIdentitySha256,
            candidateTransportAuthorizationSha256 = request.runtimeMutationPermit.candidateTransportAuthorizationSha256,
            boundedSftpImplementationId = capabilities.implementationId,
            boundedSftpCapabilityProfileSha256 = capabilitySha256,
            boundedSftpFactoryClassName = SiteRemoteSftpPrimitiveFactory::class.java.name,
            evaluatedAtEpochMillis = request.evaluatedAtEpochMillis,
            executionEvidenceExpiresAtEpochMillis = request.executionAuthorization.evidenceExpiresAtEpochMillis,
            runtimeMutationPermitExpiresAtEpochMillis = request.runtimeMutationPermit.permitExpiresAtEpochMillis,
            blockers = blockers,
            readinessSha256 = "",
        )
        return base.copy(readinessSha256 = readinessSha256(base)).also(::validate)
    }

    fun validate(descriptor: SiteProductionDeploymentTransportAcquisitionReadinessDescriptor) {
        require(descriptor.contractVersion == CONTRACT_VERSION) { "Unsupported transport-acquisition readiness contract" }
        require(descriptor.readinessOnly) { "Transport-acquisition descriptor must remain readiness-only" }
        require(!descriptor.productionTransportEnabled) { "Production transport must remain disabled" }
        require(!descriptor.authorizesTransport) { "Readiness descriptor must not authorize transport" }
        require(!descriptor.resolvesCredentials) { "Readiness descriptor must not resolve credentials" }
        require(!descriptor.acquiresSshSession) { "Readiness descriptor must not acquire SSH" }
        require(!descriptor.opensSftpChannel) { "Readiness descriptor must not open SFTP" }
        require(!descriptor.invokesCoordinator) { "Readiness descriptor must not invoke coordinator" }
        require(!descriptor.exposesDeployUiAction) { "Readiness descriptor must not expose deploy UI" }
        require(!descriptor.realVpsAccessAllowed) { "Readiness descriptor must not allow real VPS access" }
        require(descriptor.requiresSeparateTransportAcquisitionAuthorization) {
            "Separate transport-acquisition authorization must remain mandatory"
        }
        require(descriptor.requiresDurableReplayConsumptionBeforeCoordinatorInvocation) {
            "Durable replay consumption before coordinator invocation must remain mandatory"
        }
        require(descriptor.boundedSftpImplementationId == SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId) {
            "Bounded-SFTP implementation identity changed"
        }
        require(
            descriptor.boundedSftpCapabilityProfileSha256 ==
                SiteRemoteTransportPolicy.capabilityProfileSha256(SiteRemoteSftpPrimitiveFactory.CAPABILITIES),
        ) { "Bounded-SFTP capability profile changed" }
        val expectedStatus = if (descriptor.blockers.isEmpty()) {
            SiteProductionDeploymentTransportAcquisitionReadinessStatus.READY_FOR_SEPARATE_TRANSPORT_ACQUISITION
        } else {
            SiteProductionDeploymentTransportAcquisitionReadinessStatus.BLOCKED
        }
        require(descriptor.status == expectedStatus) { "Transport-acquisition readiness status does not match blockers" }
        require(descriptor.readinessSha256 == readinessSha256(descriptor.copy(readinessSha256 = ""))) {
            "Transport-acquisition readiness SHA-256 mismatch"
        }
    }

    private fun SiteProductionDeploymentAndroidCompositionDescriptor.remoteHostIdentityOrThrow(): String {
        require(sshHost == runtimeIdentity.remoteHostIdentity) { "Composition SSH host/runtime host mismatch" }
        return sshHost
    }

    private fun readinessSha256(
        descriptor: SiteProductionDeploymentTransportAcquisitionReadinessDescriptor,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(descriptor.contractVersion).append('\n')
            append("status=").append(descriptor.status.name).append('\n')
            append("readinessOnly=").append(descriptor.readinessOnly).append('\n')
            append("productionTransportEnabled=").append(descriptor.productionTransportEnabled).append('\n')
            append("authorizesTransport=").append(descriptor.authorizesTransport).append('\n')
            append("resolvesCredentials=").append(descriptor.resolvesCredentials).append('\n')
            append("acquiresSshSession=").append(descriptor.acquiresSshSession).append('\n')
            append("opensSftpChannel=").append(descriptor.opensSftpChannel).append('\n')
            append("invokesCoordinator=").append(descriptor.invokesCoordinator).append('\n')
            append("exposesDeployUiAction=").append(descriptor.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(descriptor.realVpsAccessAllowed).append('\n')
            append("requiresSeparateTransportAcquisitionAuthorization=")
                .append(descriptor.requiresSeparateTransportAcquisitionAuthorization).append('\n')
            append("requiresDurableReplayConsumptionBeforeCoordinatorInvocation=")
                .append(descriptor.requiresDurableReplayConsumptionBeforeCoordinatorInvocation).append('\n')
            append("compositionDescriptorSha256=").append(descriptor.compositionDescriptorSha256).append('\n')
            append("serverIdentitySha256=").append(descriptor.serverIdentitySha256).append('\n')
            append("runtimeSessionId=").append(descriptor.runtimeSessionId).append('\n')
            append("remoteHostIdentity=").append(descriptor.remoteHostIdentity).append('\n')
            append("executionAttemptId=").append(descriptor.executionAttemptId).append('\n')
            append("coordinatorInvocationId=").append(descriptor.coordinatorInvocationId).append('\n')
            append("readyRecordSha256=").append(descriptor.readyRecordSha256).append('\n')
            append("executionAuthorizationSha256=").append(descriptor.executionAuthorizationSha256).append('\n')
            append("runtimeMutationPermitSha256=").append(descriptor.runtimeMutationPermitSha256).append('\n')
            append("runtimeIdentitySha256=").append(descriptor.runtimeIdentitySha256).append('\n')
            append("candidateTransportAuthorizationSha256=").append(descriptor.candidateTransportAuthorizationSha256).append('\n')
            append("boundedSftpImplementationId=").append(descriptor.boundedSftpImplementationId).append('\n')
            append("boundedSftpCapabilityProfileSha256=").append(descriptor.boundedSftpCapabilityProfileSha256).append('\n')
            append("boundedSftpFactoryClassName=").append(descriptor.boundedSftpFactoryClassName).append('\n')
            append("evaluatedAtEpochMillis=").append(descriptor.evaluatedAtEpochMillis).append('\n')
            append("executionEvidenceExpiresAtEpochMillis=").append(descriptor.executionEvidenceExpiresAtEpochMillis).append('\n')
            append("runtimeMutationPermitExpiresAtEpochMillis=")
                .append(descriptor.runtimeMutationPermitExpiresAtEpochMillis).append('\n')
            descriptor.blockers.forEach { blocker ->
                append("blocker=").append(blocker.code).append('\u0000').append(blocker.detail).append('\n')
            }
        },
    )

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

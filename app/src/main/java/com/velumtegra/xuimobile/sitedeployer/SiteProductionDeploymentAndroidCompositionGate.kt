package com.velumtegra.xuimobile.sitedeployer

import android.content.Context
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeIdentity
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPolicy
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import java.security.MessageDigest

/**
 * Non-executing Android composition gate for the future production Site Deployer path.
 *
 * This gate binds only immutable/public identity evidence, the exact app-private durable replay
 * authority, and the already-reviewed bounded SFTP capability profile. It deliberately has no SSH
 * connection factory, session registry, SiteDeploymentCoordinator, SiteRemoteTransportPort, or UI
 * action dependency, so preparing a descriptor cannot connect to or mutate any server.
 */
internal object SiteProductionDeploymentAndroidCompositionGate {
    const val CONTRACT_VERSION: Int = 1

    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
    private val safeIdentityToken = Regex("^[^\\u0000\\r\\n]{1,256}$")

    fun prepare(
        context: Context,
        replayFence: SiteProductionDeploymentDurableReplayFence,
        serverAccess: ServerAccess,
        runtimeSessionId: String,
    ): SiteProductionDeploymentAndroidCompositionDescriptor {
        require(canonicalId.matches(runtimeSessionId)) {
            "Production composition runtime session id must be a canonical 8..128 character identifier"
        }
        require(safeIdentityToken.matches(serverAccess.serverId.value)) { "Server id is unsafe for production composition" }
        require(safeIdentityToken.matches(serverAccess.id.value)) { "Server access id is unsafe for production composition" }
        require(safeIdentityToken.matches(serverAccess.endpoint.host)) { "SSH host identity is unsafe for production composition" }
        require(safeIdentityToken.matches(serverAccess.username)) { "SSH username is unsafe for production composition" }

        val expectedReplayRoot = SiteProductionDeploymentAndroidReplayFence.canonicalRoot(context)
        val replaySnapshot = replayFence.snapshot()
        require(replaySnapshot.canonicalRootPath == expectedReplayRoot.path) {
            "Production replay authority is not bound to the exact Android app-private no-backup root"
        }
        require(replaySnapshot.runtimeMutationPermitMarkerCount >= 0) {
            "Runtime-mutation replay namespace is unreadable"
        }
        require(replaySnapshot.coordinatorInvocationAuthorizationMarkerCount >= 0) {
            "Coordinator-invocation replay namespace is unreadable"
        }
        require(replaySnapshot.transportAcquisitionHandoffAuthorizationMarkerCount >= 0) {
            "Transport-acquisition handoff replay namespace is unreadable"
        }

        val capabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES
        SiteRemoteTransportPolicy.validateCapabilities(capabilities)
        val capabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities)
        val parsedHostKey = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        val pinnedHostKeySha256 = when (parsedHostKey) {
            is HostKeyFingerprintParseResult.Valid -> parsedHostKey.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsedHostKey.reason)
        }
        val authMethodKind = when (serverAccess.auth) {
            is SshAuthRef.Password -> "PASSWORD_REF"
            is SshAuthRef.PrivateKey -> "PRIVATE_KEY_REF"
        }
        val serverIdentitySha256 = sha256(
            buildString {
                append("serverId=").append(serverAccess.serverId.value).append('\n')
                append("serverAccessId=").append(serverAccess.id.value).append('\n')
                append("sshHost=").append(serverAccess.endpoint.host).append('\n')
                append("sshPort=").append(serverAccess.endpoint.port).append('\n')
                append("sshUsername=").append(serverAccess.username).append('\n')
                append("sshAuthMethodKind=").append(authMethodKind).append('\n')
                append("pinnedHostKeySha256=").append(pinnedHostKeySha256).append('\n')
            },
        )
        val runtimeIdentity = SiteProductionDeploymentRuntimeIdentity(
            runtimeSessionId = runtimeSessionId,
            remoteHostIdentity = serverAccess.endpoint.host,
            transportImplementationId = capabilities.implementationId,
            capabilityProfileSha256 = capabilityProfileSha256,
        )
        val base = SiteProductionDeploymentAndroidCompositionDescriptor(
            contractVersion = CONTRACT_VERSION,
            compositionOnly = true,
            productionTransportEnabled = false,
            authorizesTransport = false,
            opensSshSession = false,
            invokesCoordinator = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresFreshReadinessEvidence = true,
            requiresExecutionAuthorization = true,
            requiresRuntimeMutationPermit = true,
            requiresDurableReplayConsumption = true,
            runtimeIdentity = runtimeIdentity,
            serverId = serverAccess.serverId.value,
            serverAccessId = serverAccess.id.value,
            sshHost = serverAccess.endpoint.host,
            sshPort = serverAccess.endpoint.port,
            sshUsername = serverAccess.username,
            sshAuthMethodKind = authMethodKind,
            pinnedHostKeySha256 = pinnedHostKeySha256,
            serverIdentitySha256 = serverIdentitySha256,
            replayFenceContractVersion = replaySnapshot.contractVersion,
            replayFenceCanonicalRootPath = replaySnapshot.canonicalRootPath,
            transportCapabilityNames = capabilities.capabilities.map { it.name },
            transportMaxFiles = capabilities.maxFiles,
            transportMaxTotalBytes = capabilities.maxTotalBytes,
            transportMaxSingleFileBytes = capabilities.maxSingleFileBytes,
            transportMaxRemotePathLength = capabilities.maxRemotePathLength,
            descriptorSha256 = "",
        )
        return base.copy(descriptorSha256 = descriptorSha256(base))
    }

    fun validate(descriptor: SiteProductionDeploymentAndroidCompositionDescriptor) {
        require(descriptor.contractVersion == CONTRACT_VERSION) { "Unsupported production composition contract" }
        require(descriptor.compositionOnly) { "Production composition descriptor must remain composition-only" }
        require(!descriptor.productionTransportEnabled) { "Production transport must remain disabled" }
        require(!descriptor.authorizesTransport) { "Composition descriptor must not authorize transport" }
        require(!descriptor.opensSshSession) { "Composition descriptor must not open SSH" }
        require(!descriptor.invokesCoordinator) { "Composition descriptor must not invoke coordinator" }
        require(!descriptor.exposesDeployUiAction) { "Composition descriptor must not expose deploy UI" }
        require(!descriptor.realVpsAccessAllowed) { "Composition descriptor must not allow real VPS access" }
        require(descriptor.requiresFreshReadinessEvidence) { "Fresh readiness evidence must remain mandatory" }
        require(descriptor.requiresExecutionAuthorization) { "Execution authorization must remain mandatory" }
        require(descriptor.requiresRuntimeMutationPermit) { "Runtime mutation permit must remain mandatory" }
        require(descriptor.requiresDurableReplayConsumption) { "Durable replay consumption must remain mandatory" }
        require(descriptor.descriptorSha256 == descriptorSha256(descriptor.copy(descriptorSha256 = ""))) {
            "Production composition descriptor SHA-256 mismatch"
        }
    }

    private fun descriptorSha256(descriptor: SiteProductionDeploymentAndroidCompositionDescriptor): String = sha256(
        buildString {
            append("contractVersion=").append(descriptor.contractVersion).append('\n')
            append("compositionOnly=").append(descriptor.compositionOnly).append('\n')
            append("productionTransportEnabled=").append(descriptor.productionTransportEnabled).append('\n')
            append("authorizesTransport=").append(descriptor.authorizesTransport).append('\n')
            append("opensSshSession=").append(descriptor.opensSshSession).append('\n')
            append("invokesCoordinator=").append(descriptor.invokesCoordinator).append('\n')
            append("exposesDeployUiAction=").append(descriptor.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(descriptor.realVpsAccessAllowed).append('\n')
            append("requiresFreshReadinessEvidence=").append(descriptor.requiresFreshReadinessEvidence).append('\n')
            append("requiresExecutionAuthorization=").append(descriptor.requiresExecutionAuthorization).append('\n')
            append("requiresRuntimeMutationPermit=").append(descriptor.requiresRuntimeMutationPermit).append('\n')
            append("requiresDurableReplayConsumption=").append(descriptor.requiresDurableReplayConsumption).append('\n')
            append("runtimeSessionId=").append(descriptor.runtimeIdentity.runtimeSessionId).append('\n')
            append("remoteHostIdentity=").append(descriptor.runtimeIdentity.remoteHostIdentity).append('\n')
            append("transportImplementationId=").append(descriptor.runtimeIdentity.transportImplementationId).append('\n')
            append("capabilityProfileSha256=").append(descriptor.runtimeIdentity.capabilityProfileSha256).append('\n')
            append("serverId=").append(descriptor.serverId).append('\n')
            append("serverAccessId=").append(descriptor.serverAccessId).append('\n')
            append("sshHost=").append(descriptor.sshHost).append('\n')
            append("sshPort=").append(descriptor.sshPort).append('\n')
            append("sshUsername=").append(descriptor.sshUsername).append('\n')
            append("sshAuthMethodKind=").append(descriptor.sshAuthMethodKind).append('\n')
            append("pinnedHostKeySha256=").append(descriptor.pinnedHostKeySha256).append('\n')
            append("serverIdentitySha256=").append(descriptor.serverIdentitySha256).append('\n')
            append("replayFenceContractVersion=").append(descriptor.replayFenceContractVersion).append('\n')
            append("replayFenceCanonicalRootPath=").append(descriptor.replayFenceCanonicalRootPath).append('\n')
            descriptor.transportCapabilityNames.forEach { append("transportCapability=").append(it).append('\n') }
            append("transportMaxFiles=").append(descriptor.transportMaxFiles).append('\n')
            append("transportMaxTotalBytes=").append(descriptor.transportMaxTotalBytes).append('\n')
            append("transportMaxSingleFileBytes=").append(descriptor.transportMaxSingleFileBytes).append('\n')
            append("transportMaxRemotePathLength=").append(descriptor.transportMaxRemotePathLength).append('\n')
        },
    )

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

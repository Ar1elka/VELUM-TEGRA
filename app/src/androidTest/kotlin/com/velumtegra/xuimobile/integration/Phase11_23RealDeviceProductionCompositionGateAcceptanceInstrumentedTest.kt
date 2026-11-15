package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPolicy
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCompositionGate
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real-device proof that Phase 11.23 composes reviewable production identity/capability evidence
 * without acquiring SSH, invoking the deployment coordinator, consuming replay authority, exposing
 * a deploy UI action, or allowing real-VPS access.
 */
@RunWith(AndroidJUnit4::class)
class Phase11_23RealDeviceProductionCompositionGateAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun productionCompositionIsExactDeterministicAndStillNonExecuting() {
        val secretId = SecretId("phase11_23_secret_ref_must_not_leak")
        val access = ServerAccess(
            id = ServerAccessId("phase11_23_access"),
            serverId = ServerId("phase11_23_server"),
            endpoint = SshEndpoint(host = "203.0.113.23", port = 2222),
            username = "velum-site",
            auth = SshAuthRef.PrivateKey(secretId),
            pinnedHostKey = CanonicalHostKeyFingerprint
                .fromRawHostKey("phase11.23-host-key".encodeToByteArray())
                .asModel(),
        )
        val before = application.siteProductionDeploymentReplayFence.snapshot()
        val first = application.siteProductionDeploymentCompositionDescriptor(
            serverAccess = access,
            runtimeSessionId = "phase11_23_runtime_0001",
        )
        val second = application.siteProductionDeploymentCompositionDescriptor(
            serverAccess = access,
            runtimeSessionId = "phase11_23_runtime_0001",
        )
        val after = application.siteProductionDeploymentReplayFence.snapshot()

        SiteProductionDeploymentAndroidCompositionGate.validate(first)
        assertEquals(first, second)
        assertEquals(first.descriptorSha256, second.descriptorSha256)
        assertEquals(
            SiteProductionDeploymentAndroidReplayFence.canonicalRoot(context).path,
            first.replayFenceCanonicalRootPath,
        )
        assertEquals(before.runtimeMutationPermitMarkerCount, after.runtimeMutationPermitMarkerCount)
        assertEquals(
            before.coordinatorInvocationAuthorizationMarkerCount,
            after.coordinatorInvocationAuthorizationMarkerCount,
        )
        assertEquals(access.serverId.value, first.serverId)
        assertEquals(access.id.value, first.serverAccessId)
        assertEquals(access.endpoint.host, first.sshHost)
        assertEquals(access.endpoint.port, first.sshPort)
        assertEquals(access.username, first.sshUsername)
        assertEquals("PRIVATE_KEY_REF", first.sshAuthMethodKind)
        assertEquals(access.endpoint.host, first.runtimeIdentity.remoteHostIdentity)
        assertEquals(SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId, first.runtimeIdentity.transportImplementationId)
        assertEquals(
            SiteRemoteTransportPolicy.capabilityProfileSha256(SiteRemoteSftpPrimitiveFactory.CAPABILITIES),
            first.runtimeIdentity.capabilityProfileSha256,
        )
        assertEquals(
            SiteRemoteSftpPrimitiveFactory.CAPABILITIES.capabilities.map { it.name },
            first.transportCapabilityNames,
        )
        assertTrue(first.compositionOnly)
        assertFalse(first.productionTransportEnabled)
        assertFalse(first.authorizesTransport)
        assertFalse(first.opensSshSession)
        assertFalse(first.invokesCoordinator)
        assertFalse(first.exposesDeployUiAction)
        assertFalse(first.realVpsAccessAllowed)
        assertTrue(first.requiresFreshReadinessEvidence)
        assertTrue(first.requiresExecutionAuthorization)
        assertTrue(first.requiresRuntimeMutationPermit)
        assertTrue(first.requiresDurableReplayConsumption)
        assertFalse("Secret reference leaked into descriptor", first.toString().contains(secretId.value))

        val changedSession = application.siteProductionDeploymentCompositionDescriptor(
            serverAccess = access,
            runtimeSessionId = "phase11_23_runtime_0002",
        )
        assertNotEquals(first.descriptorSha256, changedSession.descriptorSha256)
    }
}
